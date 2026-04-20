import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "DNSProxy")

/// Process attribution context for a single DNS flow. Bundled to keep function
/// parameter counts manageable.
private struct FlowContext {
    let pid: pid_t
    let uid: uid_t
    let path: String
}

/// DNSProxyProvider intercepts DNS queries, captures metadata for EDR telemetry,
/// and forwards queries to the originally-intended DNS server. Process attribution
/// is done via audit tokens on the incoming flow.
///
/// Uses the modern `Network.NWEndpoint`-based NEAppProxyFlow APIs (macOS 15+);
/// the legacy `NWHostEndpoint` surface is deprecated and emits build warnings.
///
/// Safety: The proxy forwards all datagrams unchanged -- parsing is best-effort
/// and only used for telemetry. If parsing fails, forwarding still succeeds.
/// The system excludes this extension's own outbound connections from the proxy
/// chain, so there's no infinite loop.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let serializer = NetworkEventSerializer()

    override func startProxy(options _: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("DNS proxy started")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("DNS proxy stopping: \(String(describing: reason))")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
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

    // MARK: - UDP flow handling

    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) {
        let (pid, uid) = extractProcessInfo(from: flow.metaData.sourceAppAuditToken)
        let ctx = FlowContext(pid: pid, uid: uid, path: processPath(for: pid))

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
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.sendUDPAndReceive(connection: connection, datagram: datagram,
                                        responseEndpoint: endpoint, flow: flow, ctx: ctx)
            case .failed(let error):
                logger.error("Upstream UDP connection failed: \(error.localizedDescription)")
                connection.cancel()
            case .cancelled:
                break
            default:
                break
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
    }

    private func sendUDPAndReceive(connection: Network.NWConnection, datagram: Data,
                                   responseEndpoint: Network.NWEndpoint, flow: NEAppProxyUDPFlow,
                                   ctx: FlowContext) {
        connection.send(content: datagram, completion: .contentProcessed { [weak self] error in
            if let error {
                logger.error("Failed to send UDP datagram: \(error.localizedDescription)")
                connection.cancel()
                return
            }
            self?.receiveUDPResponse(connection: connection, responseEndpoint: responseEndpoint,
                                     flow: flow, ctx: ctx)
        })
    }

    /// receiveUDPResponse reads the upstream DNS reply and forwards it back to the
    /// originating flow. Split out of sendUDPAndReceive so each closure holds only one
    /// level of nested asynchronous work.
    private func receiveUDPResponse(connection: Network.NWConnection, responseEndpoint: Network.NWEndpoint,
                                    flow: NEAppProxyUDPFlow, ctx: FlowContext) {
        connection.receiveMessage { [weak self] responseData, _, _, recvError in
            defer { connection.cancel() }

            if let recvError {
                logger.debug("UDP receive error: \(recvError.localizedDescription)")
                return
            }
            guard let responseData, !responseData.isEmpty else { return }

            // Enrich telemetry with response addresses.
            self?.emitDNSResponseTelemetry(response: responseData, ctx: ctx, proto: "udp")

            flow.writeDatagrams([(responseData, responseEndpoint)]) { writeError in
                if let writeError {
                    logger.error("Failed to write UDP response: \(writeError.localizedDescription)")
                }
            }
        }
    }

    // MARK: - TCP flow handling

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) {
        let (pid, uid) = extractProcessInfo(from: flow.metaData.sourceAppAuditToken)
        let ctx = FlowContext(pid: pid, uid: uid, path: processPath(for: pid))
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
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 30) {
                    connection.cancel()
                }
                return
            }

            // TCP DNS has a 2-byte length prefix; emit telemetry on the query portion.
            if let data, data.count > 2 {
                let queryData = data.suffix(from: 2)
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
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                // Emit response telemetry (TCP DNS has a 2-byte length prefix).
                if data.count > 2 {
                    self?.emitDNSResponseTelemetry(response: Data(data.dropFirst(2)), ctx: ctx, proto: "tcp")
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

    // MARK: - Telemetry

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
            proto: proto
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
            proto: proto
        )

        if let data = serializer.serialize(eventType: "dns_query", payload: payload) {
            XPCServer.shared.send(data: data)
        }
    }
}
