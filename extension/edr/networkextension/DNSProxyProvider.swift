import Foundation
import Network
import NetworkExtension
import os.log
import SystemConfiguration

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "DNSProxy")

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
        // Release the path monitor started in startProxy. stopProxy runs on configuration changes, not only at process
        // exit, so leaving it running would leak a monitor and its queue on every start/stop cycle.
        interfaces.stop()
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

        // NOTE: there is deliberately no "should we claim this flow?" question here any more (issue #673). The old
        // watchdog answered it with a bypass implemented as `return false`, which Apple documents as TERMINATING the
        // flow rather than handing it to the system resolver, so it took host DNS down instead of failing open. The
        // health accounting survives as a REPORTER only; a failing upstream is now answered by trying another system
        // resolver, not by leaving the DNS path. See DNSProxyHealth and DNSUpstreamFailover.

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
                // Emitted once per datagram, here rather than per attempt, so a failover does not produce a second
                // dns_query event for the same question (best-effort; never gates forwarding).
                self.emitDNSTelemetry(datagram: datagram, ctx: ctx, proto: "udp")
                self.forwardUDPDatagram(UDPForwardRequest(datagram: datagram, target: endpoint, replyEndpoint: endpoint,
                                                          flow: flow, ctx: ctx, route: route, isFailover: false))
            }

            // Continue reading for more datagrams on this flow.
            self.readUDPDatagrams(flow: flow, ctx: ctx, route: route)
        }
    }

    private func forwardUDPDatagram(_ request: UDPForwardRequest) {
        // Forward to the intended DNS server. The system excludes this extension's own connections from the DNS proxy
        // chain, so OUR forward cannot loop back into us. That guarantee does not extend to another network-extension
        // provider's flows, which is what `route.routing` exists to handle: those are forwarded off tunnel interfaces so
        // we cannot re-enter a tunnel whose provider is waiting on this answer (issue #656).
        let route = request.route
        let connection = Network.NWConnection(
            to: request.target,
            using: InterfaceSnapshot.udpParameters(routing: route.routing, boundInterface: route.boundInterface))

        // One outcome per ATTEMPT, resolved once. A failed first attempt does not end the query: when the client was
        // using the system's configured resolvers we try the next one before giving up (issue #673). Only the final
        // outcome is accounted, so a query rescued by the failover is not recorded as a failure.
        let completion = DNSForwardCompletion { [weak self, weak flow = request.flow] ok in
            // Break the retain cycle before cancelling: connection -> stateUpdateHandler closure -> UDPForward ->
            // completion -> (this closure captures connection). Without clearing the handler, connection, completion, and
            // the NEAppProxyUDPFlow all leak on every query. Clearing it drops the closure's strong refs.
            connection.stateUpdateHandler = nil
            connection.cancel()
            guard let self else { return }
            if ok {
                self.recordForwardOutcome(ok: true, route: route)
                return
            }
            if !request.isFailover, let flow, let retry = self.failoverRequest(for: request, flow: flow) {
                self.forwardUDPDatagram(retry)
                return
            }
            self.recordForwardOutcome(ok: false, route: route)
            // Nothing left to try: release the flow so the client fails fast rather than being pinned on a proxy that
            // cannot answer. This closes one query; it does not remove us from the DNS path, which is not something a
            // provider can do per flow without terminating it.
            flow?.closeReadWithError(nil)
            flow?.closeWriteWithError(nil)
        }
        // The deadline races the receive: failIfPending resolves to a failure only if the receive path has not already
        // claimed the forward, so a near-deadline success is never reclassified as a failure.
        let deadline = DispatchWorkItem {
            // Log only when this deadline actually wins (genuinely timed out). DispatchWorkItem.cancel() is cooperative, so
            // a deadline that starts running just as the receive path cancels it must not emit a "timed out" line on a
            // forward that ultimately succeeded: that would be a misleading operator signal / false alert.
            if completion.failIfPending() {
                logger.debug("Upstream UDP forward attempt timed out after \(DNSProxy.udpForwardDeadlineSeconds)s")
            }
        }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + DNSProxy.udpForwardDeadlineSeconds,
                                                             execute: deadline)

        let forward = UDPForward(connection: connection, responseEndpoint: request.replyEndpoint, flow: request.flow,
                                 ctx: request.ctx, completion: completion, deadline: deadline)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.sendUDPAndReceive(forward, datagram: request.datagram)
            case .failed(let error):
                logger.debug("Upstream UDP connection failed: \(error.localizedDescription)")
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

/// Failover selection and health accounting for the DNS proxy. Split into an extension so the provider's own body stays
/// within SwiftLint's type_body_length cap; same-file `private` still reaches the stored properties.
private extension DNSProxyProvider {
    /// failoverRequest builds the second attempt when the first resolver did not answer, or nil when no failover is
    /// appropriate. The selection rule (and why a client-chosen resolver is never substituted) lives in
    /// DNSUpstreamFailover; this only bridges it to Network framework types.
    func failoverRequest(for request: UDPForwardRequest, flow: NEAppProxyUDPFlow) -> UDPForwardRequest? {
        guard let failed = DNSUpstreamFailover.address(of: request.target),
              let next = DNSUpstreamFailover.nextServer(afterFailing: failed, systemServers: systemResolverAddresses()),
              let port = DNSUpstreamFailover.port(of: request.target) else { return nil }
        logger.debug("Retrying a DNS forward against another system resolver after the first did not answer")
        return UDPForwardRequest(datagram: request.datagram,
                                 target: .hostPort(host: .init(next), port: port),
                                 replyEndpoint: request.replyEndpoint,
                                 flow: flow, ctx: request.ctx, route: request.route, isFailover: true)
    }

    /// systemResolverAddresses flattens the resolver addresses from the system DNS configuration, in configuration
    /// order. Read per failover rather than cached: failovers are rare, and a cached copy would go stale across the
    /// network changes that matter most here.
    /// systemResolverAddresses reads the host's configured resolvers from the dynamic store, the same source
    /// `scutil --dns` reads.
    ///
    /// NOT `NEDNSProxyProvider.systemDNSSettings`, despite that being the obvious candidate: measured on macOS 26.3
    /// inside a running DNS proxy provider it returns nil, while the host genuinely had two resolvers configured. A
    /// failover built on it can never fire, which is worse than no failover because it implies a safety property that
    /// does not exist. The dynamic store returns the real list.
    ///
    /// Read per failover rather than cached: failovers are rare, and a cached copy would go stale across exactly the
    /// network changes that matter here.
    func systemResolverAddresses() -> [String] {
        guard let store = SCDynamicStoreCreate(nil, "com.fleetdm.edr.networkextension" as CFString, nil, nil),
              let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any],
              let servers = dns["ServerAddresses"] as? [String] else {
            logger.debug("No system resolver list available; a failing forward cannot be retried elsewhere")
            return []
        }
        return servers
    }

    /// recordForwardOutcome feeds the health accounting and logs a status change once, never per forward.
    ///
    /// Tunnel-avoiding forwards are excluded: they are denied the tunnel by design, so on a full-tunnel host they fail by
    /// construction and would drag the reported status to degraded without anything actually being wrong with the host's
    /// DNS (issue #656).
    func recordForwardOutcome(ok: Bool, route: ForwardRoute) {
        guard route.routing.feedsHealthWatchdog else { return }
        guard let status = health.record(ok: ok) else { return }
        switch status {
        case .degraded:
            logger.error("""
            DNS forwarding is degraded: upstream resolvers are not answering. Queries are being retried against other \
            system resolvers where possible; the proxy stays in the DNS path because leaving it would terminate flows
            """)
        case .healthy:
            logger.info("DNS forwarding recovered: upstream resolvers are answering again")
        }
    }

    func sendUDPAndReceive(_ forward: UDPForward, datagram: Data) {
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
    func receiveUDPResponse(_ forward: UDPForward) {
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
}
