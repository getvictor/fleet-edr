import Darwin
import Foundation
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleet.edr.networkextension", category: "NetworkFilter")

/// Returns the executable path for a given PID using proc_pidpath, or "unknown" on failure.
private func processPath(for pid: pid_t) -> String {
    guard pid > 0 else { return "unknown" }
    let bufferSize = 4 * Int(MAXPATHLEN)
    let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: bufferSize)
    defer { buffer.deallocate() }
    let result = proc_pidpath(pid, buffer, UInt32(bufferSize))
    guard result > 0 else { return "unknown" }
    return String(cString: buffer)
}

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
        var pid: pid_t = -1
        var uid: uid_t = 0
        if let token = flow.sourceAppAuditToken {
            token.withUnsafeBytes { buf in
                guard buf.count >= MemoryLayout<audit_token_t>.size else { return }
                let ptr = buf.baseAddress!.assumingMemoryBound(to: audit_token_t.self)
                pid = audit_token_to_pid(ptr.pointee)
                uid = audit_token_to_euid(ptr.pointee)
            }
        }

        let path = processPath(for: pid)

        // Determine protocol.
        let proto: String
        switch socketFlow.socketProtocol {
        case 6: proto = "tcp"
        case 17: proto = "udp"
        default: proto = "ip-\(socketFlow.socketProtocol)"
        }

        // Extract remote endpoint.
        let remoteHost: String
        let remotePort: UInt16
        if let remote = socketFlow.remoteEndpoint as? NWHostEndpoint {
            remoteHost = remote.hostname
            remotePort = UInt16(remote.port) ?? 0
        } else {
            remoteHost = ""
            remotePort = 0
        }

        // Extract local endpoint.
        let localHost: String
        let localPort: UInt16
        if let local = socketFlow.localEndpoint as? NWHostEndpoint {
            localHost = local.hostname
            localPort = UInt16(local.port) ?? 0
        } else {
            localHost = ""
            localPort = 0
        }

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
