import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "DNSProxy")

/// Wire-format + flow-control constants for DNS proxying.
private enum DNSProxy {
    /// RFC 1035 §4.2.2: TCP DNS messages are prefixed with a two-byte big-endian length.
    static let tcpLengthPrefixBytes = 2
    /// 16-bit length means the upper bound on a TCP DNS payload is UInt16.max bytes.
    static let tcpMaxMessageBytes = Int(UInt16.max)
    /// Safety cancel for an idle TCP DNS connection after the flow has signalled FIN
    /// upstream. 30s is past any sane resolver round-trip but bounded enough that a
    /// misbehaving upstream cannot pin our flow + NWConnection pair forever.
    static let tcpUpstreamLingerSeconds: Double = 30
    /// Deadline for a single UDP DNS forward (connect + send + receive). Past this the upstream is treated as failed: the
    /// flow is released (fail-open) and the failure is recorded so the health watchdog can bypass a wedged upstream. 3s is
    /// past a sane resolver round-trip but short enough that a stuck upstream cannot pin the client's resolution. Before
    /// this existed the UDP path waited on `receiveMessage` with no timeout, so a wedged upstream hung every claimed query
    /// indefinitely and took down all DNS (the 2026-06-20 incident).
    static let udpForwardDeadlineSeconds: Double = 3
}

/// Process attribution context for a single DNS flow. Bundled to keep function
/// parameter counts manageable.
private struct FlowContext {
    let pid: pid_t
    let uid: uid_t
    let path: String
    /// Kernel PID generation of the querying process when the flow carried an audit token; nil otherwise (issue #403).
    let pidVersion: UInt32?
}

/// How a claimed flow's forward must leave the host: the policy's routing decision plus the interface the client bound,
/// if any. Bundled for the same parameter-count reason FlowContext exists, and because the two are only ever meaningful
/// together (a tunnel-avoiding route deliberately ignores the bound interface).
private struct ForwardRoute {
    let routing: DNSForwardPolicy.Routing
    let boundInterface: NWInterface?
}

/// Per-datagram UDP forward state, bundled so the send / receive helpers stay under the parameter-count limit (same reason
/// FlowContext exists). One UDPForward exists per outbound query: it carries the upstream connection, the flow to write the
/// answer back to, the once-guarded completion, and the deadline timer.
private struct UDPForward {
    let connection: Network.NWConnection
    let responseEndpoint: Network.NWEndpoint
    let flow: NEAppProxyUDPFlow
    let ctx: FlowContext
    let completion: DNSForwardCompletion
    let deadline: DispatchWorkItem
}

/// DNSProxyProvider intercepts DNS queries, captures metadata for EDR telemetry,
/// and forwards queries to the originally-intended DNS server. Process attribution
/// is done via audit tokens on the incoming flow.
///
/// Uses the modern `Network.NWEndpoint`-based NEAppProxyFlow APIs (macOS 15+);
/// the legacy `NWHostEndpoint` surface is deprecated and emits build warnings.
///
/// Safety: The proxy forwards all datagrams unchanged. Parsing is best-effort
/// and only used for telemetry. If parsing fails, forwarding still succeeds.
///
/// The system keeps THIS extension's own outbound connections out of the proxy chain, so our own forward cannot loop back
/// into us. That guarantee does not extend to a second network extension that is itself a resolver, which is what issue
/// #656 broke: see DNSForwardPolicy for the deadlock and the routing that prevents it.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let serializer = NetworkEventSerializer()
    /// Self-heal watchdog. Accounts UDP upstream-forward outcomes; when forwarding is sustainedly failing it tells
    /// handleNewFlow to stop claiming DNS flows so the system resolver takes over (fail-open). See DNSProxyHealth + ADR-0014.
    private let health = DNSProxyHealth()
    /// Chooses how to route a claimed flow's forward so it can never re-enter another provider's tunnel (issue #656). Our
    /// own signing identifier is carved out because our provider holds the same entitlement the probe keys on.
    private let forwardPolicy = DNSForwardPolicy(ownSigningIdentifier: Bundle.main.bundleIdentifier ?? "")
    private let providerLookup = NetworkExtensionProviderLookup.shared
    /// Signing identifiers already reported as tunnel-avoiding, so the fact is logged once per provider rather than once
    /// per flow. Bounded by the number of network extensions installed on the host, which is a handful.
    private let notedPeers = OSAllocatedUnfairLock<Set<String>>(initialState: [])
    /// Live interface snapshot, used to pin an upstream forward to the interface the client bound its flow to. Started in
    /// startProxy so the first flow already has a snapshot to match against.
    private let interfaces = InterfaceSnapshot()

    override func startProxy(options _: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        interfaces.start()
        logger.info("DNS proxy started")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("DNS proxy stopping: \(String(describing: reason))")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let identity = extractProcessInfo(from: flow.metaData.sourceAppAuditToken)
        let signingIdentifier = flow.metaData.sourceAppSigningIdentifier

        // Decide how this flow's forward must be routed (issue #656). We deliberately do NOT decline another provider's
        // flows: returning false does not hand a DNS flow back to the system, it kills it, so declining would trade a
        // deadlock that needs a VPN for a guaranteed resolution failure. See DNSForwardPolicy for the measurement.
        let routing = forwardPolicy.routing(
            sourceSigningIdentifier: signingIdentifier,
            sourceIsNetworkExtensionProvider: providerLookup.isProvider(auditToken: flow.metaData.sourceAppAuditToken,
                                                                        identity: identity)
        )
        if routing == .avoidTunnelEgress {
            noteTunnelAvoidance(signingIdentifier: signingIdentifier)
        }

        // Self-heal watchdog. WARNING: this bypass does NOT fail open, contrary to its original design intent. Returning
        // false does not hand a DNS flow back to the system resolver: measured on edr-dev with a build that declined every
        // flow, nothing on the host resolved at all (dig against either configured resolver, dscacheutil, and ping all
        // failed), while the same queries succeeded the moment the proxy configuration was disabled. The incident record
        // agrees: the watchdog fired 18 times and host DNS recovered in none of those windows, and only disabling the
        // configuration restored it. So a bypass is a host-wide DNS outage, not a safety valve. The latch and backoff
        // added for issue #657 still bound how often we enter it and how many queries a probe stalls, which is why this is
        // left in place rather than ripped out mid-change, but the real fix is to tear down the proxy configuration
        // instead of declining flows. Tracked separately; do not add new callers of this bypass until it is.
        // policyActive is false until the network-response enforcement plane lands.
        let decision = health.decide(policyActive: false)
        if let transition = decision.transition {
            logTransition(transition)
        }
        if decision.verdict == .bypass {
            return false
        }

        // Built once here rather than per flow-type handler: the audit-token parse and proc_pidpath are the same work for
        // both, and the claim decision above already needed the identity.
        let ctx = FlowContext(pid: identity.pid, uid: identity.uid, path: processPath(for: identity.pid),
                              pidVersion: identity.pidversion)

        if let udpFlow = flow as? NEAppProxyUDPFlow {
            handleUDPFlow(udpFlow, ctx: ctx, routing: routing)
            return true
        }
        // TCP DNS is rare but must be handled to avoid breaking large responses.
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            handleTCPFlow(tcpFlow, ctx: ctx, routing: routing)
            return true
        }
        return false
    }

    /// noteTunnelAvoidance reports, once per provider, that we are keeping that provider's DNS forwards off tunnel
    /// interfaces. A per-flow line would flood the log on a host whose tunnel provider resolves continuously (the
    /// incident host produced 730 such flows in 18 minutes); the operator needs to know WHICH provider is being routed
    /// around, not how often.
    private func noteTunnelAvoidance(signingIdentifier: String) {
        let firstTime = notedPeers.withLock { $0.insert(signingIdentifier).inserted }
        guard firstTime else { return }
        logger.info("""
        Keeping DNS forwards for \(signingIdentifier, privacy: .public) off tunnel interfaces: it is itself a network \
        extension, and routing its resolver traffic back through a tunnel can deadlock host DNS
        """)
    }

    /// boundInterface resolves the interface the client bound this flow to, so an ordinary forward can be pinned to it.
    /// Only a BOUND flow yields one: an unbound flow expressed no interface preference, so forcing one on it would change
    /// routing for the overwhelmingly common case rather than honouring a choice the client actually made.
    private func boundInterface(for flow: NEAppProxyFlow) -> NWInterface? {
        guard flow.isBound, let bound = flow.networkInterface else { return nil }
        return interfaces.interface(named: String(cString: nw_interface_get_name(bound)))
    }

    // MARK: UDP flow handling

    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow, ctx: FlowContext, routing: DNSForwardPolicy.Routing) {
        // Captured before open() so the forward path does not have to reach back into the flow for it.
        let route = ForwardRoute(routing: routing, boundInterface: boundInterface(for: flow))

        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            if let error {
                logger.error("Failed to open UDP flow: \(error.localizedDescription)")
                return
            }
            self?.readUDPDatagrams(flow: flow, ctx: ctx, route: route)
        }
    }

    private func readUDPDatagrams(flow: NEAppProxyUDPFlow, ctx: FlowContext, route: ForwardRoute) {
        flow.readDatagrams { [weak self] pairs, error in
            guard let self else { return }

            if error != nil {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }
            guard let pairs, !pairs.isEmpty else {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }

            for (datagram, endpoint) in pairs {
                self.forwardUDPDatagram(datagram, to: endpoint, flow: flow, ctx: ctx, route: route)
            }

            // Continue reading for more datagrams on this flow.
            self.readUDPDatagrams(flow: flow, ctx: ctx, route: route)
        }
    }

    private func forwardUDPDatagram(_ datagram: Data, to endpoint: Network.NWEndpoint,
                                    flow: NEAppProxyUDPFlow, ctx: FlowContext, route: ForwardRoute) {
        // Emit telemetry (best-effort).
        emitDNSTelemetry(datagram: datagram, ctx: ctx, proto: "udp")

        // Forward to the originally-intended DNS server. The system excludes this
        // extension's own connections from the DNS proxy chain, so there's no
        // infinite loop.
        let connection = Network.NWConnection(
            to: endpoint,
            using: InterfaceSnapshot.udpParameters(routing: route.routing, boundInterface: route.boundInterface))

        // One outcome per forward, recorded once. On failure we fail open: cancel the upstream connection and release the
        // flow so the client retries or rolls over instead of being pinned on a wedged proxy. The recorded failure feeds
        // the health watchdog, which bypasses to the system resolver once enough forwards fail in a row.
        let completion = DNSForwardCompletion { [weak self, weak flow] ok in
            // Tunnel-avoiding forwards are excluded: they are denied the tunnel by design, so on a full-tunnel host
            // they fail by construction, and counting them would drive the watchdog toward a bypass that takes host DNS
            // down rather than opening it.
            if route.routing.feedsHealthWatchdog { self?.health.record(ok: ok) }
            // Break the retain cycle before cancelling: connection -> stateUpdateHandler closure -> UDPForward ->
            // completion -> (this closure captures connection). Without clearing the handler, connection, completion, and
            // the NEAppProxyUDPFlow all leak on every query. Clearing it drops the closure's strong refs.
            connection.stateUpdateHandler = nil
            connection.cancel()
            if !ok {
                flow?.closeReadWithError(nil)
                flow?.closeWriteWithError(nil)
            }
        }
        // The deadline races the receive: failIfPending resolves to a failure only if the receive path has not already
        // claimed the forward, so a near-deadline success is never reclassified as a failure.
        let deadline = DispatchWorkItem {
            // Log only when this deadline actually wins (genuinely timed out). DispatchWorkItem.cancel() is cooperative, so
            // a deadline that starts running just as the receive path cancels it must not emit a "timed out" line on a
            // forward that ultimately succeeded: that would be a misleading operator signal / false alert.
            if completion.failIfPending() {
                logger.error("Upstream UDP forward timed out after \(DNSProxy.udpForwardDeadlineSeconds, format: .fixed(precision: 0))s")
            }
        }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + DNSProxy.udpForwardDeadlineSeconds,
                                                             execute: deadline)

        let forward = UDPForward(connection: connection, responseEndpoint: endpoint, flow: flow, ctx: ctx,
                                 completion: completion, deadline: deadline)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.sendUDPAndReceive(forward, datagram: datagram)
            case .failed(let error):
                logger.error("Upstream UDP connection failed: \(error.localizedDescription)")
                deadline.cancel()
                completion.failIfPending()
            case .cancelled:
                break
            default:
                break
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
    }

    private func sendUDPAndReceive(_ forward: UDPForward, datagram: Data) {
        forward.connection.send(content: datagram, completion: .contentProcessed { [weak self] error in
            if let error {
                logger.error("Failed to send UDP datagram: \(error.localizedDescription)")
                forward.deadline.cancel()
                forward.completion.failIfPending()
                return
            }
            self?.receiveUDPResponse(forward)
        })
    }

    /// receiveUDPResponse reads the upstream DNS reply and forwards it back to the
    /// originating flow. Split out of sendUDPAndReceive so each closure holds only one
    /// level of nested asynchronous work.
    private func receiveUDPResponse(_ forward: UDPForward) {
        forward.connection.receiveMessage { [weak self] responseData, _, _, recvError in
            forward.deadline.cancel()

            // Atomically claim the forward before touching the flow. If the deadline already won (fail-open, flow closed),
            // claimResponse returns false and a late reply emits no spurious telemetry and does not write to the closed
            // flow. Once claimed, the deadline's failIfPending is a no-op, so this success cannot be reclassified.
            guard forward.completion.claimResponse() else { return }

            if let recvError {
                logger.debug("UDP receive error: \(recvError.localizedDescription)")
                forward.completion.resolveResponse(ok: false)
                return
            }
            guard let responseData, !responseData.isEmpty else {
                forward.completion.resolveResponse(ok: false)
                return
            }

            // Enrich telemetry with response addresses.
            self?.emitDNSResponseTelemetry(response: responseData, ctx: forward.ctx, proto: "udp")

            forward.flow.writeDatagrams([(responseData, forward.responseEndpoint)]) { writeError in
                if let writeError {
                    logger.error("Failed to write UDP response: \(writeError.localizedDescription)")
                    forward.completion.resolveResponse(ok: false)
                    return
                }
                // Upstream answered and the client received it: a healthy forward.
                forward.completion.resolveResponse(ok: true)
            }
        }
    }

    // MARK: TCP flow handling

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow, ctx: FlowContext, routing: DNSForwardPolicy.Routing) {
        let upstreamEndpoint = flow.remoteFlowEndpoint
        let pinned = boundInterface(for: flow)

        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            if let error {
                logger.error("Failed to open TCP flow: \(error.localizedDescription)")
                return
            }

            let connection = Network.NWConnection(
                to: upstreamEndpoint,
                using: InterfaceSnapshot.tcpParameters(routing: routing, boundInterface: pinned))
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.pumpTCP(flow: flow, connection: connection, ctx: ctx)
                case .failed(let error):
                    logger.error("TCP connection failed: \(error.localizedDescription)")
                    flow.closeReadWithError(error)
                    flow.closeWriteWithError(error)
                    connection.cancel()
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
        }
    }

    private func pumpTCP(flow: NEAppProxyTCPFlow, connection: Network.NWConnection, ctx: FlowContext) {
        // Flow -> upstream
        readTCPFromFlow(flow: flow, connection: connection, ctx: ctx)
        // Upstream -> flow
        readTCPFromConnection(flow: flow, connection: connection, ctx: ctx)
    }

    private func readTCPFromFlow(flow: NEAppProxyTCPFlow, connection: Network.NWConnection, ctx: FlowContext) {
        flow.readData { [weak self] data, error in
            guard let self else { return }

            if error != nil || data == nil || data?.isEmpty == true {
                // Flow-closed / empty read → send an NWConnection FIN upstream so the
                // upstream side also unwinds. Always close our write side of the flow
                // and arm a bounded safety cancel so a misbehaving upstream that never
                // EOFs back can't pin the flow + NWConnection pair forever. On an
                // explicit flow error, propagate it to both sides and cancel
                // immediately rather than waiting on the reader goroutine.
                if let error {
                    flow.closeReadWithError(error)
                    flow.closeWriteWithError(error)
                    connection.cancel()
                    return
                }
                connection.send(content: nil, contentContext: .finalMessage,
                                isComplete: true, completion: .contentProcessed { _ in
                                    // Intentional no-op; the dispatch below force-cancels
                                    // if the upstream reader hasn't already torn down.
                                })
                flow.closeWriteWithError(nil)
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + DNSProxy.tcpUpstreamLingerSeconds) {
                    connection.cancel()
                }
                return
            }

            // TCP DNS has a 2-byte length prefix; emit telemetry on the query portion.
            if let data, data.count > DNSProxy.tcpLengthPrefixBytes {
                let queryData = data.suffix(from: DNSProxy.tcpLengthPrefixBytes)
                self.emitDNSTelemetry(datagram: Data(queryData), ctx: ctx, proto: "tcp")
            }

            connection.send(content: data, completion: .contentProcessed { sendError in
                if let sendError {
                    flow.closeReadWithError(sendError)
                    flow.closeWriteWithError(sendError)
                    connection.cancel()
                    return
                }
                self.readTCPFromFlow(flow: flow, connection: connection, ctx: ctx)
            })
        }
    }

    private func readTCPFromConnection(flow: NEAppProxyTCPFlow, connection: Network.NWConnection, ctx: FlowContext) {
        connection.receive(minimumIncompleteLength: 1,
                           maximumLength: DNSProxy.tcpMaxMessageBytes) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                // Emit response telemetry (TCP DNS has a 2-byte length prefix).
                if data.count > DNSProxy.tcpLengthPrefixBytes {
                    self?.emitDNSResponseTelemetry(
                        response: Data(data.dropFirst(DNSProxy.tcpLengthPrefixBytes)),
                        ctx: ctx, proto: "tcp")
                }
                flow.write(data) { writeError in
                    if let writeError {
                        flow.closeReadWithError(writeError)
                        flow.closeWriteWithError(writeError)
                        connection.cancel()
                        return
                    }
                    self?.readTCPFromConnection(flow: flow, connection: connection, ctx: ctx)
                }
            }
            if isComplete || error != nil {
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                connection.cancel()
            }
        }
    }

    // MARK: Telemetry

    private func emitDNSTelemetry(datagram: Data, ctx: FlowContext, proto: String) {
        guard let queryName = DNSParser.queryName(from: datagram) else { return }
        let queryType = DNSParser.queryType(from: datagram)

        logger.debug(
            "DNS query: \(queryName, privacy: .private(mask: .hash)) (\(queryType)) pid=\(ctx.pid)"
        )

        let payload = DNSQueryPayload(
            pid: ctx.pid, path: ctx.path, uid: ctx.uid,
            queryName: queryName, queryType: queryType,
            responseAddresses: nil,
            proto: proto,
            pidVersion: ctx.pidVersion
        )

        if let data = serializer.serialize(eventType: "dns_query", payload: payload) {
            XPCServer.shared.send(data: data)
        }
    }

    private func emitDNSResponseTelemetry(response: Data, ctx: FlowContext, proto: String) {
        guard let queryName = DNSParser.queryName(from: response) else { return }
        let queryType = DNSParser.queryType(from: response)
        let responseAddrs = DNSParser.responseAddresses(from: response)

        guard !responseAddrs.isEmpty else { return }

        let payload = DNSQueryPayload(
            pid: ctx.pid, path: ctx.path, uid: ctx.uid,
            queryName: queryName, queryType: queryType,
            responseAddresses: responseAddrs,
            proto: proto,
            pidVersion: ctx.pidVersion
        )

        if let data = serializer.serialize(eventType: "dns_query", payload: payload) {
            XPCServer.shared.send(data: data)
        }
    }
}

/// Operator-facing logging for the DNS proxy. Split into an extension so the provider's own body stays within SwiftLint's
/// type_body_length cap and so the flow-handling logic reads without the message text interleaved.
private extension DNSProxyProvider {
    /// logTransition emits one line per watchdog state change. Logged from the single decide() call that produced the
    /// change, never per flow: every DNS lookup reaches handleNewFlow, so a per-flow line would be the log flood the
    /// watchdog exists to prevent. The three cases are distinct messages on purpose. During the 2026-07-27 incident the
    /// log carried nothing but repeated "entering bypass", which left no way to tell one sustained bypass from the
    /// re-trip loop that was actually happening.
    func logTransition(_ transition: DNSProxyHealth.Transition) {
        switch transition {
        case .enteredBypass(let trip, let hold):
            logger.error("""
            DNS proxy entering bypass (consecutive trip \(trip, format: .decimal)): upstream forwarding sustainedly \
            failing; handing DNS to the system resolver for \(hold, format: .fixed(precision: 0))s
            """)
        case .startedProbe(let trip, let budget):
            logger.info("""
            DNS proxy probing upstream after bypass hold (consecutive trip \(trip, format: .decimal)): claiming up to \
            \(budget, format: .decimal) flows; all others stay on the system resolver
            """)
        case .resumed:
            logger.info("DNS proxy resuming: upstream healthy, claiming DNS flows again")
        }
    }
}
