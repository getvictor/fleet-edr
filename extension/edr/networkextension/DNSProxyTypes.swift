import Foundation
import Network
import NetworkExtension

// Plumbing types for the DNS proxy: the wire-format and flow-control constants, and the small bundles that keep the
// provider's helper signatures under SwiftLint's parameter-count cap. Split out of DNSProxyProvider.swift so that file
// stays within the file-length cap. They are internal rather than private only because they now live in a sibling file;
// nothing outside the network extension target uses them.

/// Wire-format + flow-control constants for DNS proxying.
enum DNSProxy {
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
struct FlowContext {
    let pid: pid_t
    let uid: uid_t
    let path: String
    /// Kernel PID generation of the querying process when the flow carried an audit token; nil otherwise (issue #403).
    let pidVersion: UInt32?
}

/// How a claimed flow's forward must leave the host: the policy's routing decision plus the interface the client bound,
/// if any. Bundled for the same parameter-count reason FlowContext exists, and because the two are only ever meaningful
/// together (a tunnel-avoiding route deliberately ignores the bound interface).
struct ForwardRoute {
    let routing: DNSForwardPolicy.Routing
    let boundInterface: NWInterface?
}

/// Per-datagram UDP forward state, bundled so the send / receive helpers stay under the parameter-count limit (same reason
/// FlowContext exists). One UDPForward exists per outbound query: it carries the upstream connection, the flow to write the
/// answer back to, the once-guarded completion, and the deadline timer.
struct UDPForward {
    let connection: Network.NWConnection
    let responseEndpoint: Network.NWEndpoint
    let flow: NEAppProxyUDPFlow
    let ctx: FlowContext
    let completion: DNSForwardCompletion
    let deadline: DispatchWorkItem
}
