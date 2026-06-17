import Foundation

// Network / DNS event payload wire types, defined in their own file (separate from NetworkEventSerializer.swift, whose
// EventEnvelope would collide with the system-extension serializer's copy in the shared SwiftPM logic module). Keeping the
// plain Codable structs here lets `swift test` exercise their wire shape directly, including the optional `pidversion` key
// (issue #403): the synthesized encoder emits it when set and omits it when nil, which the NetworkConnectPayload /
// DNSQueryPayload encoding tests pin so a wire-key regression on the NetworkExtension surface is caught (Copilot review).

struct NetworkConnectPayload: Codable, Sendable {
    let pid: pid_t
    let path: String
    let uid: uid_t
    let proto: String
    let direction: String
    let localAddress: String
    let localPort: UInt16
    let remoteAddress: String
    let remotePort: UInt16
    let remoteHostname: String
    /// Kernel PID generation (audit_token_to_pidversion) of the source process, when the flow carried an audit token. Lets the
    /// server correlate the flow to the exact process generation independently of PID reuse (issue #403). The synthesized
    /// encoder omits the key when nil, keeping the wire shape compact and backwards-tolerant for legacy agents.
    let pidVersion: UInt32?

    enum CodingKeys: String, CodingKey {
        case pid, path, uid
        case proto = "protocol"
        case direction
        case localAddress = "local_address"
        case localPort = "local_port"
        case remoteAddress = "remote_address"
        case remotePort = "remote_port"
        case remoteHostname = "remote_hostname"
        case pidVersion = "pidversion"
    }
}

struct DNSQueryPayload: Codable, Sendable {
    let pid: pid_t
    let path: String
    let uid: uid_t
    let queryName: String
    let queryType: String
    let responseAddresses: [String]?
    let proto: String
    /// Kernel PID generation of the querying process, when the flow carried an audit token (issue #403). The DNS proxy only
    /// has sourceAppAuditToken (NEFlowMetaData exposes no per-process token), so this is the app token's pidversion. Omitted
    /// from the wire when nil by the synthesized encoder.
    let pidVersion: UInt32?

    enum CodingKeys: String, CodingKey {
        case pid, path, uid
        case queryName = "query_name"
        case queryType = "query_type"
        case responseAddresses = "response_addresses"
        case proto = "protocol"
        case pidVersion = "pidversion"
    }
}
