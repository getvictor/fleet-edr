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

    var order: PushOrder { PushOrder(epoch: epoch, version: version) }

    /// supersedes reports whether this update should replace `current`, in PushOrder. Commands can reach the host out of order, and a
    /// delayed release applied over a newer containment would free a host an operator just contained.
    func supersedes(_ current: NetworkContainmentUpdate?) -> Bool {
        guard let current else { return true }
        return order > current.order
    }

    /// refreshesLifeline reports whether this update is the current containment with a different server endpoint. The agent re-resolves
    /// the server name while the host is contained and sends the same server state with the addresses it now resolves to, so an update
    /// at the same epoch and version is accepted when only the lifeline moved.
    func refreshesLifeline(_ current: NetworkContainmentUpdate?) -> Bool {
        guard let current else { return false }
        return order == current.order && contained == current.contained
            && (serverPort != current.serverPort || serverAddresses != current.serverAddresses)
    }
}

/// LifelineRule is one flow a contained host may still carry, in the terms of an NENetworkRule: a remote address and prefix, a remote
/// port (0 for any), a local port when the flow must come from one, a transport, and a direction.
struct LifelineRule: Equatable, Sendable {
    enum Transport: Sendable { case tcp, udp }
    enum Direction: Sendable { case outbound, any }

    let address: String
    let prefix: Int
    let port: UInt16
    let localPort: UInt16?
    let transport: Transport
    let direction: Direction

    init(address: String, prefix: Int, port: UInt16, localPort: UInt16? = nil, transport: Transport, direction: Direction) {
        self.address = address
        self.prefix = prefix
        self.port = port
        self.localPort = localPort
        self.transport = transport
        self.direction = direction
    }
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
    private static let dhcpClientPort: UInt16 = 68
    private static let dhcpv6ServerPort: UInt16 = 547
    private static let dhcpv6ClientPort: UInt16 = 546
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
    /// the server port, which carries the agent's uploads, commands and the release itself. It is DHCP, between the client port (68,
    /// or 546 for DHCPv6) and the server port (67, or 547): measured, a lease renewal during containment otherwise loses the host's
    /// address, and with it the route to the server. Requiring the client port, which only a privileged process can bind, keeps the
    /// rule from carrying arbitrary UDP to port 67; it allows either direction because a server's offer arrives as its own flow. And
    /// it is DNS (TCP and UDP 53), outbound only, so an inbound flow from source port 53 reaches nothing: every lookup on the host
    /// passes through this extension's DNS proxy, whose own forwards are subject to these settings, so without it the agent cannot
    /// resolve the server name.
    static func lifeline(for update: NetworkContainmentUpdate) -> [LifelineRule] {
        guard update.contained else { return [] }
        var rules = update.serverAddresses.map { address in
            LifelineRule(address: address, prefix: isIPv6(address) ? ipv6HostPrefix : ipv4HostPrefix, port: update.serverPort,
                         transport: .tcp, direction: .outbound)
        }
        for (any, server, client) in [("0.0.0.0", dhcpServerPort, dhcpClientPort), ("::", dhcpv6ServerPort, dhcpv6ClientPort)] {
            rules.append(LifelineRule(address: any, prefix: 0, port: server, localPort: client, transport: .udp, direction: .any))
            rules.append(LifelineRule(address: any, prefix: 0, port: dnsPort, transport: .udp, direction: .outbound))
            rules.append(LifelineRule(address: any, prefix: 0, port: dnsPort, transport: .tcp, direction: .outbound))
        }
        return rules
    }

    /// isUsableAddress accepts an IPv4 or IPv6 literal other than the unspecified address, which as a lifeline would match nothing. A
    /// string with an embedded NUL is refused before parsing, since inet_pton would read only the part before it.
    static func isUsableAddress(_ address: String) -> Bool {
        guard !address.contains("\u{0}") else { return false }
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

/// ContainmentSequencer is NetworkContainmentController's bookkeeping for applying filter settings, kept free of NetworkExtension so
/// its orderings are unit-testable. The controller calls it on its serial queue and performs the applies it asks for.
///
/// One apply is in flight at a time, and a request while one is in flight is deferred until it completes, so settings never take
/// effect out of order. A filter's start completion is ignored once that filter has stopped, and a completion from a filter other than
/// the running one is not reported, since it no longer describes the host. Stopped filters are held weakly, so a new filter that reuses
/// a released one's address is not mistaken for it.
final class ContainmentSequencer<Filter: AnyObject> {
    enum StartDecision: Equatable {
        /// The filter had already stopped; nothing changes.
        case ignore
        /// The startup settings enforce the current state; report it as applied.
        case report
        /// The current state differs from what started, or startup failed; apply it now.
        case apply
        /// An apply is in flight; the current state is applied to this filter when it completes.
        case wait
    }

    enum ApplyDecision {
        case apply(Filter)
        /// An apply is in flight; this request is applied when it completes.
        case deferred
        /// No filter is running; the state is applied when one starts.
        case noFilter
    }

    private weak var running: Filter?
    private let stopped = NSHashTable<Filter>.weakObjects()
    private var applying = false
    private var reapply = false

    func started(_ filter: Filter, startupEnforcesCurrent: Bool) -> StartDecision {
        guard !stopped.contains(filter) else { return .ignore }
        running = filter
        if applying {
            reapply = true
            return .wait
        }
        return startupEnforcesCurrent ? .report : .apply
    }

    /// stopped records that filter stopped, and returns whether it was the running filter. A stop from a filter that was already
    /// replaced changes nothing about the running one.
    @discardableResult
    func stopped(_ filter: Filter) -> Bool {
        stopped.add(filter)
        guard running === filter else { return false }
        running = nil
        return true
    }

    func requestApply() -> ApplyDecision {
        guard !applying else {
            reapply = true
            return .deferred
        }
        guard let filter = running else { return .noFilter }
        applying = true
        reapply = false
        return .apply(filter)
    }

    /// completed records that an apply to filter finished. report says whether its result describes the host now; applyAgain says
    /// whether a request made while it was in flight needs the current state applied. A replacement filter that started meanwhile is
    /// one such request, since started defers to the apply in flight.
    func completed(_ filter: Filter) -> (report: Bool, applyAgain: Bool) {
        applying = false
        return (filter === running && !reapply, reapply)
    }
}

/// ContainmentStatusTracker is what NetworkContainmentController knows about applying the held state, kept free of NetworkExtension so
/// the reported status is unit-testable. The status is derived from it and the held state, never cached, so it always describes the
/// state the extension holds.
struct ContainmentStatusTracker {
    /// applied is the state the running filter was last confirmed to enforce; error is why the held state is not applied, when an
    /// attempt failed or found no filter running.
    private(set) var applied: NetworkContainmentUpdate?
    private(set) var error: String?

    /// accepted notes a newly accepted update: whatever went wrong before concerned an earlier state.
    mutating func accepted() {
        error = nil
    }

    /// confirmed notes that the running filter enforces update.
    mutating func confirmed(_ update: NetworkContainmentUpdate?) {
        applied = update
        error = nil
    }

    /// failed notes that applying the held state failed, or that no filter is running to apply it. The running filter is then not
    /// confirmed to enforce anything, whatever an earlier filter did.
    mutating func failed(_ reason: String) {
        applied = nil
        error = reason
    }

    /// status is what the extension reports for the held state: applied when the running filter was confirmed to enforce exactly that
    /// state, pending (not applied, no error) while it waits, and not applied with the error when the latest attempt failed.
    func status(held: NetworkContainmentUpdate) -> NetworkContainmentStatus {
        // Confirming clears the error and failing clears the confirmation, so an applied state never carries one.
        NetworkContainmentStatus(contained: held.contained, version: held.version, epoch: held.epoch, applied: held == applied,
                                 error: error)
    }
}
