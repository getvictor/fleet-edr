import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.victoronsoftware.edr.networkextension", category: "DNSProxy")

/// Disambiguates the NWEndpoint type that comes from NetworkExtension (NEAppProxyFlow APIs).
/// The Network framework's NWEndpoint uses a different type name via typealias.
private typealias FlowEndpoint = NWHostEndpoint

/// DNSProxyProvider intercepts DNS queries, captures metadata for EDR telemetry,
/// and forwards queries to the originally-intended DNS server. Process attribution
/// is done via audit tokens on the incoming flow.
///
/// Safety: The proxy forwards all datagrams unchanged -- parsing is best-effort
/// and only used for telemetry. If parsing fails, forwarding still succeeds.
/// The system excludes this extension's own outbound connections from the proxy
/// chain, so there's no infinite loop.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let serializer = NetworkEventSerializer()

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
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
        let path = processPath(for: pid)

        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error {
                logger.error("Failed to open UDP flow: \(error.localizedDescription)")
                return
            }
            self?.readUDPDatagrams(flow: flow, pid: pid, uid: uid, path: path)
        }
    }

    private func readUDPDatagrams(flow: NEAppProxyUDPFlow, pid: pid_t, uid: uid_t, path: String) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self else { return }

            if error != nil {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }

            guard let datagrams, let endpoints, !datagrams.isEmpty else {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }

            for i in 0..<datagrams.count {
                // Cast to NWHostEndpoint (which is the concrete subclass the framework returns).
                if let hostEndpoint = endpoints[i] as? NWHostEndpoint {
                    self.forwardUDPDatagram(datagrams[i], to: hostEndpoint, flow: flow, pid: pid, uid: uid, path: path)
                }
            }

            // Continue reading for more datagrams on this flow.
            self.readUDPDatagrams(flow: flow, pid: pid, uid: uid, path: path)
        }
    }

    private func forwardUDPDatagram(_ datagram: Data, to endpoint: NWHostEndpoint, flow: NEAppProxyUDPFlow,
                                    pid: pid_t, uid: uid_t, path: String) {
        // Emit telemetry (best-effort).
        emitDNSTelemetry(datagram: datagram, pid: pid, uid: uid, path: path)

        // Forward to the originally-intended DNS server using Network framework.
        // The system excludes this extension's own connections from the DNS proxy chain,
        // so there's no infinite loop.
        guard let upstreamEndpoint = convertToNetworkEndpoint(endpoint) else {
            logger.error("Failed to convert endpoint; dropping datagram")
            return
        }

        let connection = Network.NWConnection(to: upstreamEndpoint, using: .udp)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.sendUDPAndReceive(connection: connection, datagram: datagram,
                                        responseEndpoint: endpoint, flow: flow, pid: pid, uid: uid, path: path)
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
                                   responseEndpoint: NWHostEndpoint, flow: NEAppProxyUDPFlow,
                                   pid: pid_t, uid: uid_t, path: String) {
        connection.send(content: datagram, completion: .contentProcessed { [weak self] error in
            if let error {
                logger.error("Failed to send UDP datagram: \(error.localizedDescription)")
                connection.cancel()
                return
            }

            connection.receiveMessage { [weak self] responseData, _, _, recvError in
                defer { connection.cancel() }

                if let recvError {
                    logger.debug("UDP receive error: \(recvError.localizedDescription)")
                    return
                }

                guard let responseData, !responseData.isEmpty else { return }

                // Enrich telemetry with response addresses.
                self?.emitDNSResponseTelemetry(response: responseData, pid: pid, uid: uid, path: path)

                // Write response back to the originating flow.
                flow.writeDatagrams([responseData], sentBy: [responseEndpoint]) { writeError in
                    if let writeError {
                        logger.error("Failed to write UDP response: \(writeError.localizedDescription)")
                    }
                }
            }
        })
    }

    // MARK: - TCP flow handling

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) {
        let (pid, uid) = extractProcessInfo(from: flow.metaData.sourceAppAuditToken)
        let path = processPath(for: pid)

        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint,
              let upstreamEndpoint = convertToNetworkEndpoint(remoteEndpoint) else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error {
                logger.error("Failed to open TCP flow: \(error.localizedDescription)")
                return
            }

            let connection = Network.NWConnection(to: upstreamEndpoint, using: .tcp)
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.pumpTCP(flow: flow, connection: connection, pid: pid, uid: uid, path: path)
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

    private func pumpTCP(flow: NEAppProxyTCPFlow, connection: Network.NWConnection,
                         pid: pid_t, uid: uid_t, path: String) {
        // Flow -> upstream
        readTCPFromFlow(flow: flow, connection: connection, pid: pid, uid: uid, path: path)
        // Upstream -> flow
        readTCPFromConnection(flow: flow, connection: connection)
    }

    private func readTCPFromFlow(flow: NEAppProxyTCPFlow, connection: Network.NWConnection,
                                 pid: pid_t, uid: uid_t, path: String) {
        flow.readData { [weak self] data, error in
            guard let self else { return }

            if error != nil || data == nil || data?.isEmpty == true {
                connection.send(content: nil, contentContext: .finalMessage,
                                isComplete: true, completion: .contentProcessed { _ in })
                return
            }

            // TCP DNS has a 2-byte length prefix; emit telemetry on the query portion.
            if let data, data.count > 2 {
                let queryData = data.suffix(from: 2)
                self.emitDNSTelemetry(datagram: Data(queryData), pid: pid, uid: uid, path: path)
            }

            connection.send(content: data, completion: .contentProcessed { sendError in
                if sendError != nil {
                    flow.closeWriteWithError(sendError)
                    return
                }
                self.readTCPFromFlow(flow: flow, connection: connection, pid: pid, uid: uid, path: path)
            })
        }
    }

    private func readTCPFromConnection(flow: NEAppProxyTCPFlow, connection: Network.NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                flow.write(data) { writeError in
                    if writeError == nil {
                        self?.readTCPFromConnection(flow: flow, connection: connection)
                    }
                }
            }
            if isComplete || error != nil {
                flow.closeReadWithError(nil)
                connection.cancel()
            }
        }
    }

    // MARK: - Endpoint conversion

    /// Converts a NWHostEndpoint (or NWHostEndpoint) to a Network.NWEndpoint.
    private func convertToNetworkEndpoint(_ endpoint: NWHostEndpoint) -> Network.NWEndpoint? {
        guard let hostEndpoint = endpoint as? NWHostEndpoint else { return nil }
        guard let port = UInt16(hostEndpoint.port) else { return nil }
        let host = Network.NWEndpoint.Host(hostEndpoint.hostname)
        // swiftlint:disable:next force_unwrapping
        return .hostPort(host: host, port: Network.NWEndpoint.Port(rawValue: port)!)
    }

    // MARK: - Telemetry

    private func emitDNSTelemetry(datagram: Data, pid: pid_t, uid: uid_t, path: String) {
        guard let queryName = DNSParser.queryName(from: datagram) else { return }
        let queryType = DNSParser.queryType(from: datagram)

        logger.debug("DNS query: \(queryName, privacy: .public) (\(queryType)) pid=\(pid) path=\(path, privacy: .public)")

        let payload = DNSQueryPayload(
            pid: pid, path: path, uid: uid,
            queryName: queryName, queryType: queryType,
            responseAddresses: nil,
            proto: "udp"
        )

        if let data = serializer.serialize(eventType: "dns_query", payload: payload) {
            XPCServer.shared.send(data: data)
        }
    }

    private func emitDNSResponseTelemetry(response: Data, pid: pid_t, uid: uid_t, path: String) {
        guard let queryName = DNSParser.queryName(from: response) else { return }
        let queryType = DNSParser.queryType(from: response)
        let responseAddrs = DNSParser.responseAddresses(from: response)

        guard !responseAddrs.isEmpty else { return }

        let payload = DNSQueryPayload(
            pid: pid, path: path, uid: uid,
            queryName: queryName, queryType: queryType,
            responseAddresses: responseAddrs,
            proto: "udp"
        )

        if let data = serializer.serialize(eventType: "dns_query", payload: payload) {
            XPCServer.shared.send(data: data)
        }
    }
}
