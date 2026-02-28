import Foundation
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleet.edr.networkextension", category: "NetworkFilter")

/// NetworkFilter captures outbound network connections and DNS queries,
/// attributing them to the source process via audit token.
final class NetworkFilter: NEFilterDataProvider {
    nonisolated(unsafe) var onEvent: ((Data) -> Void)?
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
                let auditToken = buf.load(as: audit_token_t.self)
                pid = audit_token_to_pid(auditToken)
                uid = audit_token_to_euid(auditToken)
            }
        }

        let path = flow.sourceAppIdentifier ?? "unknown"

        // Determine protocol.
        let proto: String
        switch socketFlow.socketProtocol {
        case 6: proto = "tcp"
        case 17: proto = "udp"
        default: proto = "other"
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
            onEvent?(data)
        }

        return .filterDataVerdict(withFilterInbound: isDNSFlow(proto: proto, port: remotePort),
                                  peekInboundBytes: isDNSFlow(proto: proto, port: remotePort) ? 512 : 0,
                                  filterOutbound: isDNSFlow(proto: proto, port: remotePort),
                                  peekOutboundBytes: isDNSFlow(proto: proto, port: remotePort) ? 512 : 0)
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset: Int, readBytes: Data) -> NEFilterDataVerdict {
        // Parse outbound DNS queries (UDP port 53).
        if let query = parseDNSQuery(readBytes) {
            var pid: pid_t = -1
            var uid: uid_t = 0
            if let token = flow.sourceAppAuditToken {
                token.withUnsafeBytes { buf in
                    guard buf.count >= MemoryLayout<audit_token_t>.size else { return }
                    let auditToken = buf.load(as: audit_token_t.self)
                    pid = audit_token_to_pid(auditToken)
                    uid = audit_token_to_euid(auditToken)
                }
            }

            let payload = DNSQueryPayload(
                pid: pid,
                path: flow.sourceAppIdentifier ?? "unknown",
                uid: uid,
                queryName: query.name,
                queryType: query.type,
                responseAddresses: [],
                proto: "udp"
            )

            if let data = serializer.serialize(eventType: "dns_query", payload: payload) {
                onEvent?(data)
            }
        }

        return .allow()
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset: Int, readBytes: Data) -> NEFilterDataVerdict {
        // We could parse DNS responses here, but for the pilot we capture
        // queries in handleOutboundData and leave response parsing as future work.
        return .allow()
    }

    private func isDNSFlow(proto: String, port: UInt16) -> Bool {
        return proto == "udp" && port == 53
    }
}

// MARK: - Minimal DNS parser

private struct DNSQuestion {
    let name: String
    let type: String
}

/// Parses a DNS query from raw UDP payload. Only extracts the question name and type.
/// Returns nil if the data doesn't look like a valid DNS query.
private func parseDNSQuery(_ data: Data) -> DNSQuestion? {
    // DNS header is 12 bytes minimum.
    guard data.count >= 12 else { return nil }

    let bytes = Array(data)

    // QR bit (bit 7 of byte 2) should be 0 for queries.
    let qr = (bytes[2] >> 7) & 1
    guard qr == 0 else { return nil }

    // QDCOUNT (bytes 4-5).
    let qdcount = (Int(bytes[4]) << 8) + Int(bytes[5])
    guard qdcount >= 1 else { return nil }

    // Parse question name starting at byte 12.
    var offset = 12
    var labels: [String] = []

    while offset < bytes.count {
        let labelLen = Int(bytes[offset])
        if labelLen == 0 {
            offset += 1
            break
        }
        // Compression pointer (shouldn't appear in queries, but guard against it).
        if labelLen >= 0xC0 {
            return nil
        }
        guard offset + 1 + labelLen <= bytes.count else { return nil }
        let label = String(bytes: bytes[(offset + 1)..<(offset + 1 + labelLen)], encoding: .utf8) ?? ""
        labels.append(label)
        offset += 1 + labelLen
    }

    // Need at least 4 more bytes for QTYPE and QCLASS.
    guard offset + 4 <= bytes.count else { return nil }

    let qtype = (Int(bytes[offset]) << 8) + Int(bytes[offset + 1])

    let typeName: String
    switch qtype {
    case 1: typeName = "A"
    case 28: typeName = "AAAA"
    case 5: typeName = "CNAME"
    case 15: typeName = "MX"
    case 2: typeName = "NS"
    case 12: typeName = "PTR"
    case 16: typeName = "TXT"
    default: typeName = "TYPE\(qtype)"
    }

    return DNSQuestion(name: labels.joined(separator: "."), type: typeName)
}
