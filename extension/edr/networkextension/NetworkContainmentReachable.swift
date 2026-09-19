import Foundation

/// The operator-chosen destinations a contained host may still reach (issue #1059).
///
/// Kept beside NetworkContainment rather than inside it: the lifeline the product builds for itself (the server, DHCP, the host's own
/// resolvers) is one concern, and what an operator chose to add to it is another.
extension NetworkContainment {
    /// addressAndBits is a CIDR split into its two halves, which is what a slash means here.
    private static let addressAndBits = 2

    /// maxReachable bounds the operator-chosen destinations. The server caps the set it stores, and this is the extension not taking
    /// that on trust: a document naming more than a deployment could have configured is one this build does not understand.
    static let maxReachable = 64

    /// reachableRules allow the destinations an operator chose to keep reachable while a host is contained (issue #1059).
    ///
    /// An entry that cannot be turned into a rule is DROPPED rather than refusing the containment, which is the same choice
    /// resolverRules makes and for a stronger reason here: the server validated these before storing them, so a drop means the two
    /// disagree, and the direction to fail in is a host contained with one allowance missing rather than a host not contained at all.
    ///
    /// An entry naming no transport becomes both, because an operator who named only an address meant the destination and not a
    /// protocol. Direction is outbound: this opens what the host may reach, never what may reach it.
    static func reachableRules(for entries: [ReachableEntry]) -> [LifelineRule] {
        var rules: [LifelineRule] = []
        for entry in entries.prefix(maxReachable) {
            guard let (address, prefix) = parsePrefix(entry.cidr) else { continue }
            let port = entry.port ?? 0
            guard (0...Int(UInt16.max)).contains(port) else { continue }
            let transports: [LifelineRule.Transport]
            switch entry.transport?.lowercased() {
            case "tcp": transports = [.tcp]
            case "udp": transports = [.udp]
            case nil, "": transports = [.tcp, .udp]
            default: continue
            }
            for transport in transports {
                rules.append(LifelineRule(address: address, prefix: prefix, port: UInt16(port), transport: transport,
                                          direction: .outbound))
            }
        }
        return rules
    }

    /// parsePrefix splits "address/bits" into the pieces a rule needs, defaulting a bare address to a single-address prefix. It
    /// returns nil for anything this build cannot express, which the caller drops.
    static func parsePrefix(_ cidr: String) -> (address: String, prefix: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let address = String(parts[0])
        guard isUsableAddress(address) else { return nil }
        let hostPrefix = isIPv6(address) ? ipv6HostPrefix : ipv4HostPrefix
        guard parts.count == addressAndBits else { return (address, hostPrefix) }
        guard let bits = Int(parts[1]), (0...hostPrefix).contains(bits) else { return nil }
        return (address, bits)
    }
}
