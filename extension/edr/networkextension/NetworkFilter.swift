import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "NetworkFilter")

/// IANA L4 protocol numbers we attribute by name. Anything else falls through to
/// "ip-N". Mirrors <netinet/in.h>'s IPPROTO_* values.
private enum IANAProtocol {
    static let tcp: Int32 = 6
    static let udp: Int32 = 17
}

/// NetworkFilter captures outbound network connections, attributing them
/// to the source process via audit token.
///
/// DNS query capture is not implemented here because macOS routes DNS
/// through mDNSResponder, so this filter never sees application DNS flows.
/// A future NEDNSProxyProvider can intercept queries when DNS monitoring is added.
final class NetworkFilter: NEFilterDataProvider {
    private let serializer = NetworkEventSerializer()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in
            if let error {
                logger.error("Failed to apply filter settings: \(error.localizedDescription)")
            } else {
                logger.info("Network filter started")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Network filter stopping: \(String(describing: reason))")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Extract process info from the audit token. Prefer sourceProcessAuditToken (macOS 13+): the audit token of the
        // process that actually created the flow, so its (pid, pidversion) matches the socket-owning process Endpoint
        // Security observed. For a process that makes its own connection it is identical to sourceAppAuditToken; it differs
        // only for a flow a system process created on behalf of an app, which is the deferred proxied-flow case. Fall back to
        // sourceAppAuditToken when the process token is nil (issue #403).
        let info = extractProcessInfo(from: flow.sourceProcessAuditToken ?? flow.sourceAppAuditToken)

        let path = processPath(for: info.pid)

        // Determine protocol.
        let proto: String
        switch socketFlow.socketProtocol {
        case IANAProtocol.tcp: proto = "tcp"
        case IANAProtocol.udp: proto = "udp"
        default: proto = "ip-\(socketFlow.socketProtocol)"
        }

        // Extract remote + local endpoints off the modern Network.NWEndpoint
        // accessors (macOS 15+); the legacy NWHostEndpoint casts are deprecated.
        let (remoteHost, remotePort) = hostPort(from: socketFlow.remoteFlowEndpoint)
        let (localHost, localPort) = hostPort(from: socketFlow.localFlowEndpoint)

        // Extract hostname from flow URL (available via SNI for HTTPS).
        let hostname = flow.url?.host ?? ""

        let payload = NetworkConnectPayload(
            pid: info.pid,
            path: path,
            uid: info.uid,
            proto: proto,
            direction: socketFlow.direction == .outbound ? "outbound" : "inbound",
            localAddress: localHost,
            localPort: localPort,
            remoteAddress: remoteHost,
            remotePort: remotePort,
            remoteHostname: hostname,
            pidVersion: info.pidversion
        )

        if let data = serializer.serialize(eventType: "network_connect", payload: payload) {
            XPCServer.shared.send(data: data)
        }

        return .allow()
    }
}

/// hostPort destructures a Network.NWEndpoint.hostPort into (host-string, port).
/// Returns ("", 0) for nil or for non-hostPort variants (service, unix-path, url).
/// None of those variants are emitted into the network_connect telemetry today.
private func hostPort(from endpoint: Network.NWEndpoint?) -> (String, UInt16) {
    guard let endpoint, case let .hostPort(host, port) = endpoint else {
        return ("", 0)
    }
    let hostStr: String
    switch host {
    case .name(let name, _):
        hostStr = name
    case .ipv4(let addr):
        hostStr = addr.debugDescription
    case .ipv6(let addr):
        hostStr = addr.debugDescription
    @unknown default:
        hostStr = String(describing: host)
    }
    return (hostStr, port.rawValue)
}
