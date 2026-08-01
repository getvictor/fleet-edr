import Foundation
import Network

/// DNSUpstreamFailover picks a second resolver to try when the first forward of a query fails.
///
/// Why this exists (issue #673). The proxy used to respond to sustained forwarding failure by declining flows, which
/// terminates them and takes host DNS down. Declining is gone. The honest alternative when one upstream will not answer
/// is to try another one, which keeps us in the DNS path, keeps `dns_query` telemetry, and actually resolves the query.
///
/// The scoping rule is what makes this safe. A failover is offered ONLY when the client was already using the system's
/// configured resolvers. In that case any other system resolver is a legitimate substitute: it is exactly what
/// `mDNSResponder` does when it rotates across the resolvers in the system configuration, so the answer the client gets
/// is the answer the system would have produced without us.
///
/// When the client named a resolver that is NOT in the system configuration (`dig @8.8.8.8`, a container's own resolver,
/// a split-horizon corporate server reached deliberately), no failover is offered. Substituting a different server there
/// would answer a question the client did not ask: split-horizon zones resolve differently per resolver, so a "helpful"
/// retry could hand back a wrong address for an internal name. A failed lookup is the correct outcome, and it is the same
/// outcome the client would get without the proxy in the path.
///
/// Foundation and Network only, no NetworkExtension import, so the selection rule is unit-testable without a live
/// resolver or a provider instance.
enum DNSUpstreamFailover {
    /// Chooses a resolver to try after `failedServer` did not answer: the first configured resolver that is not the
    /// one that just failed. That is not round-robin, and it deliberately may be earlier in the list than the failed
    /// one; there is only ever one retry, so "the first other resolver" is the whole policy.
    ///
    /// `failedServer` is the resolver address the client's query was aimed at, as it appeared on the flow, and
    /// `systemServers` holds the resolver addresses from the system DNS configuration in configuration order. Returns the
    /// first system resolver other than the failed one, or nil when no failover is appropriate.
    static func nextServer(afterFailing failedServer: String?, systemServers: [String]) -> String? {
        guard let failedServer, !failedServer.isEmpty else { return nil }
        // The client chose a resolver outside the system configuration: respect that choice and do not substitute.
        guard systemServers.contains(where: { sameAddress($0, failedServer) }) else { return nil }
        return systemServers.first { !sameAddress($0, failedServer) }
    }

    /// sameAddress compares two resolver addresses by VALUE rather than by string.
    ///
    /// The two sides come from different places and need not spell an address the same way: the failed server is
    /// rendered from an `NWEndpoint` on the flow, while the candidates come from the dynamic store. A textual compare
    /// would miss `fd00::1` against `fd00:0:0:0:0:0:0:1` and fail closed, silently disabling the failover for a host
    /// whose resolver happens to be written in the other form. Parsing both sides removes the ambiguity; a hostname
    /// resolver (not an IP literal) still falls back to a case-sensitive string match, which is what it is.
    static func sameAddress(_ lhs: String, _ rhs: String) -> Bool {
        let left = withoutScope(lhs)
        let right = withoutScope(rhs)
        if left == right { return true }
        if let a = IPv6Address(left), let b = IPv6Address(right) { return a.rawValue == b.rawValue }
        if let a = IPv4Address(left), let b = IPv4Address(right) { return a.rawValue == b.rawValue }
        return false
    }

    /// withoutScope drops an interface scope (`fe80::1%en0`), which the flow carries and the system configuration
    /// does not.
    private static func withoutScope(_ address: String) -> String {
        address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
    }

    /// address renders an endpoint's host for comparison against the system resolver list. The interface scope on a
    /// link-local address (`fe80::1%en0`) is dropped, because the system configuration lists these unscoped and the two
    /// would otherwise never compare equal.
    static func address(of endpoint: NWEndpoint) -> String? {
        guard case .hostPort(let host, _) = endpoint else { return nil }
        let rendered: String
        switch host {
        case .ipv4(let addr): rendered = "\(addr)"
        case .ipv6(let addr): rendered = "\(addr)"
        case .name(let name, _): rendered = name
        @unknown default: return nil
        }
        return withoutScope(rendered)
    }

    /// port extracts the port to reuse for the failover attempt, so a resolver on a non-standard port stays on it.
    static func port(of endpoint: NWEndpoint) -> NWEndpoint.Port? {
        guard case .hostPort(_, let port) = endpoint else { return nil }
        return port
    }
}
