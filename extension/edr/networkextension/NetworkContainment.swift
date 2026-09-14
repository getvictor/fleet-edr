import Foundation
import os

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "NetworkContainment")

/// NetworkContainmentUpdate is a decoded `network_containment.update`: whether the host is contained, the version and epoch that order
/// it against earlier updates, and the EDR server endpoint the host must keep reaching while contained.
struct NetworkContainmentUpdate: Equatable, Sendable {
    let version: Int64
    /// epoch is the server's update time for the containment state in Unix microseconds, 0 when none was sent. It orders updates
    /// across a server database restore that sends version backwards, as it does for application control and the watched-path set.
    let epoch: Int64
    let contained: Bool
    /// serverPort and serverAddresses are the EDR server as the agent resolved it. Empty when the host is not contained.
    let serverPort: UInt16
    let serverAddresses: [String]

    /// supersedes reports whether this update should replace `current`, ordered by epoch, then version. Commands can reach the host
    /// out of order, and a delayed release applied over a newer containment would free a host an operator just contained.
    func supersedes(_ current: NetworkContainmentUpdate?) -> Bool {
        guard let current else { return true }
        return (epoch, version) > (current.epoch, current.version)
    }

    /// refreshesLifeline reports whether this update is the current containment with a different server endpoint. The agent re-resolves
    /// the server name while the host is contained and sends the same server state with the addresses it now resolves to, so an update
    /// at the same epoch and version is accepted when only the lifeline moved.
    func refreshesLifeline(_ current: NetworkContainmentUpdate?) -> Bool {
        guard let current else { return false }
        return (epoch, version) == (current.epoch, current.version) && contained == current.contained
            && (serverPort != current.serverPort || serverAddresses != current.serverAddresses)
    }
}

/// LifelineRule is one flow a contained host may still carry, in the terms of an NENetworkRule: a remote address and prefix, a remote
/// port (0 for any), a transport, and a direction.
struct LifelineRule: Equatable, Sendable {
    enum Transport: Sendable { case tcp, udp }
    enum Direction: Sendable { case outbound, any }

    let address: String
    let prefix: Int
    let port: UInt16
    let transport: Transport
    let direction: Direction
}

/// NetworkContainment is the pure half of host network containment (#948): decoding a containment document and deciding what a
/// contained host keeps. NetworkContainmentController applies the result as content-filter settings.
///
/// Containment is enforced by the operating system rather than decided per flow. Measured on macOS 26.3, filter settings whose
/// default action is drop cut established connections to other addresses within a second and hold while the provider is stopped or
/// restarting, where per-flow verdicts leave established connections open and leak new ones for seconds after a provider restart.
enum NetworkContainment {
    /// maxServerAddresses bounds the lifeline. A server name resolves to a handful of addresses; a document naming more is not one
    /// the agent produces.
    static let maxServerAddresses = 16

    /// The ports and prefixes of the lifeline beyond the server itself.
    private static let dhcpServerPort: UInt16 = 67
    private static let dhcpv6ServerPort: UInt16 = 547
    private static let dnsPort: UInt16 = 53
    private static let ipv4HostPrefix = 32
    private static let ipv6HostPrefix = 128

    private struct Document: Decodable {
        let version: Int64
        let epoch: Int64?
        let contained: Bool
        let server: Server?
    }

    private struct Server: Decodable {
        let port: Int
        let addresses: [String]
    }

    /// decode reads a `network_containment.update` payload. It returns nil, leaving the current state in force, for a payload that is
    /// not a containment document, and for a containment that names no usable lifeline: an unparseable or unspecified address, too
    /// many addresses, or a port outside 1 to 65535. Applying such a document would cut the host off from the server that has to
    /// release it, so it is refused whole rather than applied with what could be salvaged.
    static func decode(_ data: Data) -> NetworkContainmentUpdate? {
        guard let document = try? JSONDecoder().decode(Document.self, from: data) else {
            return nil
        }
        guard document.contained else {
            return NetworkContainmentUpdate(
                version: document.version, epoch: document.epoch ?? 0, contained: false, serverPort: 0, serverAddresses: []
            )
        }
        guard let server = document.server, (1...Int(UInt16.max)).contains(server.port), !server.addresses.isEmpty,
              server.addresses.count <= maxServerAddresses, server.addresses.allSatisfy(isUsableAddress) else {
            return nil
        }
        return NetworkContainmentUpdate(
            version: document.version, epoch: document.epoch ?? 0, contained: true, serverPort: UInt16(server.port),
            serverAddresses: server.addresses
        )
    }

    /// lifeline is every flow a contained host keeps, and nothing for a host that is not contained. It is TCP to each server address on
    /// the server port, which carries the agent's uploads, commands and the release itself. It is DHCP (UDP 67, and 547 for DHCPv6):
    /// measured, a lease renewal during containment otherwise loses the host's address, and with it the route to the server. And it is
    /// DNS (TCP and UDP 53): every lookup on the host passes through this extension's DNS proxy, whose own forwards are subject to these
    /// settings, so without it the agent cannot resolve the server name.
    static func lifeline(for update: NetworkContainmentUpdate) -> [LifelineRule] {
        guard update.contained else { return [] }
        var rules = update.serverAddresses.map { address in
            LifelineRule(address: address, prefix: isIPv6(address) ? ipv6HostPrefix : ipv4HostPrefix, port: update.serverPort,
                         transport: .tcp, direction: .outbound)
        }
        for (any, dhcp) in [("0.0.0.0", dhcpServerPort), ("::", dhcpv6ServerPort)] {
            rules.append(LifelineRule(address: any, prefix: 0, port: dhcp, transport: .udp, direction: .any))
            rules.append(LifelineRule(address: any, prefix: 0, port: dnsPort, transport: .udp, direction: .any))
            rules.append(LifelineRule(address: any, prefix: 0, port: dnsPort, transport: .tcp, direction: .any))
        }
        return rules
    }

    /// isUsableAddress accepts an IPv4 or IPv6 literal other than the unspecified address, which as a lifeline would match nothing.
    static func isUsableAddress(_ address: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            return v4.s_addr != 0
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { bytes in bytes.contains { $0 != 0 } }
        }
        return false
    }

    private static func isIPv6(_ address: String) -> Bool {
        address.contains(":")
    }
}

/// NetworkContainmentStatus is what the extension reports about containment: the update it holds and whether the content filter
/// applied it. The agent reports it on, so the console can tell a host that has been told to contain from one that is contained.
struct NetworkContainmentStatus: Codable, Equatable, Sendable {
    let contained: Bool
    let version: Int64
    let epoch: Int64
    let applied: Bool
    let error: String?

    /// eventType is the control event type the agent filters on, as it does for provider status.
    static let eventType = "ne_containment_status"
}

/// NetworkContainmentStore keeps the last accepted containment state: on disk, so a restarted extension re-applies it before the agent
/// is back, and in memory, so a delayed older update is turned away.
final class NetworkContainmentStore: Sendable {
    /// defaultStoragePath sits beside the application-control snapshot and the watched-path set.
    static let defaultStoragePath = "/var/db/com.fleetdm.edr/network-containment.json"

    let storagePath: String
    private let accepted: OSAllocatedUnfairLock<NetworkContainmentUpdate?>

    init(storagePath: String = NetworkContainmentStore.defaultStoragePath) {
        self.storagePath = storagePath
        self.accepted = OSAllocatedUnfairLock(initialState: nil)
        let persisted = load()
        accepted.withLock { $0 = persisted }
    }

    /// current is the last accepted update, or nil when none has been, which is a host that is not contained.
    var current: NetworkContainmentUpdate? {
        accepted.withLock { $0 }
    }

    /// accept decodes a pushed payload and, when it supersedes the current state or refreshes its lifeline and has been persisted, records
    /// it and returns it for the caller to apply. It returns nil, changing nothing, for a payload decode refuses, an update that is neither
    /// newer nor a lifeline refresh, or one that could not be written. Persisting first keeps the applied state and the one a restart
    /// loads the same.
    func accept(_ data: Data) -> NetworkContainmentUpdate? {
        guard let update = NetworkContainment.decode(data), update.supersedes(current) || update.refreshesLifeline(current),
              save(data) else {
            return nil
        }
        accepted.withLock { $0 = update }
        return update
    }

    private func load() -> NetworkContainmentUpdate? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: storagePath)) else {
            return nil
        }
        guard let update = NetworkContainment.decode(data) else {
            logger.error("persisted network containment state could not be decoded; the host starts uncontained")
            return nil
        }
        return update
    }

    private func save(_ data: Data) -> Bool {
        do {
            try AtomicFile.write(data, toPath: storagePath)
            return true
        } catch {
            logger.error("network containment not applied, persist failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }
}
