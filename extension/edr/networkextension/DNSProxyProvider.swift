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
/// The system excludes this extension's own outbound connections from the proxy
/// chain, so there's no infinite loop.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let serializer = NetworkEventSerializer()
    /// Self-heal watchdog. Accounts UDP upstream-forward outcomes; when forwarding is sustainedly failing it tells
    /// handleNewFlow to stop claiming DNS flows so the system resolver takes over (fail-open). See DNSProxyHealth + ADR-0014.
    private let health = DNSProxyHealth()

    override func startProxy(options _: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("DNS proxy started")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("DNS proxy stopping: \(String(describing: reason))")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Self-heal: if upstream forwarding is sustainedly wedged, do NOT claim the flow. Returning false hands the flow
        // to the system resolver, so a broken proxy fails open instead of taking down all DNS (the 2026-06-20 incident).
        // We lose dns_query telemetry for the bypass window, which is the correct trade for a monitoring tap. policyActive
        // is false until the network-response enforcement plane lands; an active policy will force claim + rebuild instead
        // of bypass so a blocked domain can never resolve via the system resolver (see resilient-network-enforcement).
        let decision = health.decide(policyActive: false)
        if decision.verdict == .bypass {
            if decision.transitioned {
                logger.error("DNS proxy entering bypass: upstream forwarding sustainedly failing; handing DNS to the system resolver")
            }
            return false
        }
        if decision.transitioned {
            // verdict flipped back to .claim: we just exited a bypass window (upstream recovered, or the failure samples
            // aged out so we are probing again). Logged once, not per flow.
            logger.info("DNS proxy resuming: claiming DNS flows again after a bypass window")
        }

        if let udpFlow = flow as? NEAppProxyUDPFlow {
            handleUDPFlow(udpFlow)
            return true
        }
        // TCP DNS is rare but must be handled to avoid breaking large responses.
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            handleTCPFlow(tcpFlow)
            return true
        }
        return false
    }

    // MARK: UDP flow handling

    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) {
        let info = extractProcessInfo(from: flow.metaData.sourceAppAuditToken)
        let ctx = FlowContext(pid: info.pid, uid: info.uid, path: processPath(for: info.pid), pidVersion: info.pidversion)

        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            if let error {
                logger.error("Failed to open UDP flow: \(error.localizedDescription)")
                return
            }
            self?.readUDPDatagrams(flow: flow, ctx: ctx)
        }
    }

    private func readUDPDatagrams(flow: NEAppProxyUDPFlow, ctx: FlowContext) {
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
                self.forwardUDPDatagram(datagram, to: endpoint, flow: flow, ctx: ctx)
            }

            // Continue reading for more datagrams on this flow.
            self.readUDPDatagrams(flow: flow, ctx: ctx)
        }
    }

    private func forwardUDPDatagram(_ datagram: Data, to endpoint: Network.NWEndpoint,
                                    flow: NEAppProxyUDPFlow, ctx: FlowContext) {
        // Emit telemetry (best-effort).
        emitDNSTelemetry(datagram: datagram, ctx: ctx, proto: "udp")

        // Forward to the originally-intended DNS server. The system excludes this
        // extension's own connections from the DNS proxy chain, so there's no
        // infinite loop.
        let connection = Network.NWConnection(to: endpoint, using: .udp)

        // One outcome per forward, recorded once. On failure we fail open: cancel the upstream connection and release the
        // flow so the client retries or rolls over instead of being pinned on a wedged proxy. The recorded failure feeds
        // the health watchdog, which bypasses to the system resolver once enough forwards fail in a row.
        let completion = DNSForwardCompletion { [weak self, weak flow] ok in
            self?.health.record(ok: ok)
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

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) {
        let info = extractProcessInfo(from: flow.metaData.sourceAppAuditToken)
        let ctx = FlowContext(pid: info.pid, uid: info.uid, path: processPath(for: info.pid), pidVersion: info.pidversion)
        let upstreamEndpoint = flow.remoteFlowEndpoint

        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            if let error {
                logger.error("Failed to open TCP flow: \(error.localizedDescription)")
                return
            }

            let connection = Network.NWConnection(to: upstreamEndpoint, using: .tcp)
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
