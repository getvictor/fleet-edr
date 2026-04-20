import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "NetworkFilter")

/// NetworkFilter captures outbound network connections, attributing them
/// to the source process via audit token.
///
/// DNS query capture is not implemented here because macOS routes DNS
/// through mDNSResponder, so this filter never sees application DNS flows.
/// DNS monitoring is planned for Phase 3 via NEDNSProxyProvider.
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

        // Extract process info from audit token.
        let (pid, uid) = extractProcessInfo(from: flow.sourceAppAuditToken)

        let path = processPath(for: pid)

        // Determine protocol.
        let proto: String
        switch socketFlow.socketProtocol {
        case 6: proto = "tcp"
        case 17: proto = "udp"
        default: proto = "ip-\(socketFlow.socketProtocol)"
        }

        // Extract remote + local endpoints off the modern Network.NWEndpoint
        // accessors (macOS 15+); the legacy NWHostEndpoint casts are deprecated.
        let (remoteHost, remotePort) = hostPort(from: socketFlow.remoteFlowEndpoint)
        let (localHost, localPort) = hostPort(from: socketFlow.localFlowEndpoint)

        // Extract hostname from flow URL (available via SNI for HTTPS).
        let hostname = flow.url?.host ?? ""

        let payload = NetworkConnectPayload(
            pid: pid,
            path: path,
            uid: uid,
            proto: proto,
            direction: socketFlow.direction == .outbound ? "outbound" : "inbound",
            localAddress: localHost,
            localPort: localPort,
            remoteAddress: remoteHost,
            remotePort: remotePort,
            remoteHostname: hostname
        )

        if let data = serializer.serialize(eventType: "network_connect", payload: payload) {
            XPCServer.shared.send(data: data)
        }

        return .allow()
    }
}

/// hostPort destructures a Network.NWEndpoint.hostPort into (host-string, port).
/// Returns ("", 0) for nil or for non-hostPort variants (service, unix-path, url)
/// — none of which we emit into the network_connect telemetry today.
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
