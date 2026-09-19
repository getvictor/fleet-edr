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
    /// serverPort and serverAddresses are the EDR server as the agent resolved it, and serverNames the host names the DNS proxy still
    /// resolves while the host is contained (normalized: lowercase, no trailing dot). Empty when the host is not contained.
    let serverPort: UInt16
    let serverAddresses: [String]
    let serverNames: [String]
    /// reachableVersion identifies the reachable-address set these entries came from, and is what tells one set from another: the
    /// entries themselves are not compared, so a set edited back to its previous contents is still a change the host is told about.
    let reachableVersion: Int64
    let reachable: [NetworkContainment.ReachableEntry]

    init(version: Int64, epoch: Int64, contained: Bool, serverPort: UInt16, serverAddresses: [String], serverNames: [String] = [],
         reachableVersion: Int64 = 0, reachable: [NetworkContainment.ReachableEntry] = []) {
        self.version = version
        self.epoch = epoch
        self.contained = contained
        self.serverPort = serverPort
        self.serverAddresses = serverAddresses
        self.serverNames = serverNames
        self.reachableVersion = reachableVersion
        self.reachable = reachable
    }

    var order: PushOrder { PushOrder(epoch: epoch, version: version) }

    /// supersedes reports whether this update should replace `current`, in PushOrder. Commands can reach the host out of order, and a
    /// delayed release applied over a newer containment would free a host an operator just contained.
    func supersedes(_ current: NetworkContainmentUpdate?) -> Bool {
        guard let current else { return true }
        return order > current.order
    }

    /// refreshesLifeline reports whether this update is the current containment with a lifeline that moved. The agent re-resolves the
    /// server name while the host is contained and sends the same server state with the addresses it now resolves to, so an update at
    /// the same epoch and version is accepted when only the lifeline moved.
    ///
    /// The reachable set counts as part of that lifeline, because it changes without any host's containment state changing. It is
    /// compared with GREATER THAN rather than inequality: versions only ever increase, so an update naming a lower one is a document
    /// built before the change and delayed on its way here, and accepting it would roll the host's allowances back.
    func refreshesLifeline(_ current: NetworkContainmentUpdate?) -> Bool {
        guard let current else { return false }
        return order == current.order && contained == current.contained
            && (serverPort != current.serverPort || serverAddresses != current.serverAddresses || serverNames != current.serverNames
                || reachableVersion > current.reachableVersion)
    }
}

/// ResolverLifeline remembers which resolvers the filter settings in force were built from, so the DNS half of the lifeline cannot be
/// left behind by a list that moved while no filter was running to carry it (issue #1069).
///
/// The settings are built from a snapshot of the host's configured resolvers, and that snapshot can go stale in two ways: the read
/// that warms it lands after a starting filter already built its settings, and the list changes while the content filter is down. In
/// both cases the state the extension holds is unchanged, so nothing else asks for the settings to be applied again; without this the
/// host would keep whatever DNS rules it started with until its next containment change.
struct ResolverLifeline {
    /// The resolvers the settings in force name. Nil before any settings were applied, which is not the same as an empty list: a host
    /// whose resolvers are genuinely unknown has settings that name none, and re-applying those would be work for nothing.
    private(set) var applied: [String]?

    mutating func recordApplied(_ resolvers: [String]) {
        applied = resolvers
    }

    /// needsApply says whether settings built now would name different resolvers than the ones in force.
    func needsApply(for current: [String]) -> Bool {
        applied != current
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
    /// maxServerNames bounds the names the DNS proxy resolves while contained: the server, or the proxy it is reached through.
    static let maxServerNames = 4
    /// maxResolvers bounds the DNS half of the lifeline. A host configures a handful of resolvers; a list longer than this is a
    /// configuration this extension will not turn into rules, and the first addresses of it are the ones the host queries first.
    static let maxResolvers = 8

    /// The ports and prefixes of the lifeline beyond the server itself.
    private static let dhcpServerPort: UInt16 = 67
    private static let dhcpClientPort: UInt16 = 68
    private static let dhcpv6ServerPort: UInt16 = 547
    private static let dhcpv6ClientPort: UInt16 = 546
    private static let dnsPort: UInt16 = 53
    static let ipv4HostPrefix = 32
    static let ipv6HostPrefix = 128

    private struct Document: Decodable {
        let version: Int64
        let epoch: Int64?
        let contained: Bool
        let server: Server?
        /// Optional so a document persisted by an extension that predates the reachable-address set still decodes. A host that
        /// upgrades while contained would otherwise fail to load its own state and come up uncontained (issue #1059).
        let reachableVersion: Int64?
        let reachable: [ReachableEntry]?
    }

    /// ReachableEntry is one operator-chosen destination as the agent sends it. The operator's note is not carried: it names the
    /// destination for a human reading the console, and nothing here reads it.
    struct ReachableEntry: Decodable, Equatable, Sendable {
        let cidr: String
        let port: Int?
        let transport: String?
    }

    private struct Server: Decodable {
        let port: Int
        let addresses: [String]
        let names: [String]?
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
        let names = document.server?.names ?? []
        guard let server = document.server, (1...Int(UInt16.max)).contains(server.port), !server.addresses.isEmpty,
              server.addresses.count <= maxServerAddresses, server.addresses.allSatisfy(isUsableAddress),
              names.count <= maxServerNames, names.allSatisfy(isHostName) else {
            return nil
        }
        return NetworkContainmentUpdate(
            version: document.version, epoch: document.epoch ?? 0, contained: true, serverPort: UInt16(server.port),
            serverAddresses: server.addresses, serverNames: names.map(ContainedDNS.normalized),
            reachableVersion: document.reachableVersion ?? 0, reachable: document.reachable ?? []
        )
    }

    /// lifeline is every flow a contained host keeps, and nothing for a host that is not contained. It is TCP to each server address on
    /// the server port, which carries the agent's uploads, commands and the release itself. It is DHCP, between the client port (68,
    /// or 546 for DHCPv6) and the server port (67, or 547): measured, a lease renewal during containment otherwise loses the host's
    /// address, and with it the route to the server. Requiring the client port, which only a privileged process can bind, keeps the
    /// rule from carrying arbitrary UDP to port 67; it allows either direction because a server's offer arrives as its own flow. And
    /// it is DNS (TCP and UDP 53), outbound only, so an inbound flow from source port 53 reaches nothing, and only to the resolvers
    /// passed in: the agent resolves the server name through them, and this extension's DNS proxy forwards through them as well.
    ///
    /// DNS is restricted to those addresses rather than allowed to any, because the name restriction that makes a contained host's
    /// DNS safe lives in the DNS proxy, and containment does not require the proxy to be running (issue #1069). A host whose proxy is
    /// off, stopped or wedged would otherwise keep an open path for any process to send arbitrary DNS to a resolver of its choosing,
    /// which carries data out of the host as readily as any other protocol. With no resolvers known the host gets no DNS at all: that
    /// is the same set the agent's own resolver queries, so a host that cannot be told them cannot resolve the server either way, and
    /// the agent reaches the server through the addresses the containment pinned.
    static func lifeline(for update: NetworkContainmentUpdate, resolvers: [String]) -> [LifelineRule] {
        guard update.contained else { return [] }
        var rules = serverRules(for: update)
        for (any, server, client) in [("0.0.0.0", dhcpServerPort, dhcpClientPort), ("::", dhcpv6ServerPort, dhcpv6ClientPort)] {
            rules.append(LifelineRule(address: any, prefix: 0, port: server, localPort: client, transport: .udp, direction: .any))
        }
        rules.append(contentsOf: resolverRules(for: resolvers))
        rules.append(contentsOf: reachableRules(for: update.reachable))
        return rules
    }

    /// resolverRules allow DNS to each configured resolver, over UDP and TCP. Addresses that are not usable literals are dropped
    /// rather than refusing the containment: the list comes from the host's own configuration, not from the server, so one entry the
    /// extension cannot turn into a rule must not cost the host its containment. Duplicates are collapsed by VALUE, through the same
    /// comparison the DNS failover path uses, so two spellings of one address (`fd00::1` and `fd00:0:0:0:0:0:0:1`) cannot take two of
    /// the slots under the cap and crowd out a resolver the host actually needs.
    static func resolverRules(for resolvers: [String]) -> [LifelineRule] {
        var accepted: [String] = []
        for address in resolvers where isUsableAddress(address) {
            guard !accepted.contains(where: { DNSUpstreamFailover.sameAddress($0, address) }) else { continue }
            accepted.append(address)
            guard accepted.count < maxResolvers else { break }
        }
        return accepted.flatMap { address -> [LifelineRule] in
            let prefix = isIPv6(address) ? ipv6HostPrefix : ipv4HostPrefix
            return [
                LifelineRule(address: address, prefix: prefix, port: dnsPort, transport: .udp, direction: .outbound),
                LifelineRule(address: address, prefix: prefix, port: dnsPort, transport: .tcp, direction: .outbound)
            ]
        }
    }

    /// serverRules are the lifeline's flows to the EDR server: TCP to each server address on the server port.
    static func serverRules(for update: NetworkContainmentUpdate) -> [LifelineRule] {
        update.serverAddresses.map { address in
            LifelineRule(address: address, prefix: isIPv6(address) ? ipv6HostPrefix : ipv4HostPrefix, port: update.serverPort,
                         transport: .tcp, direction: .outbound)
        }
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

    /// isHostName accepts a DNS host name: at most 253 characters without a trailing dot, of dot-separated labels of 1 to 63 letters,
    /// digits and hyphens that neither start nor end with a hyphen.
    static func isHostName(_ name: String) -> Bool {
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        // An empty name splits into one empty label, which the label check refuses.
        guard trimmed.utf8.count <= maxHostNameBytes else { return false }
        return trimmed.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.utf8.count <= maxLabelBytes && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-") }
        }
    }

    private static let maxHostNameBytes = 253
    private static let maxLabelBytes = 63

    static func isIPv6(_ address: String) -> Bool {
        address.contains(":")
    }
}

/// ReleasedLifeline is what a release keeps allowed: TCP to the server endpoint of the containment it released, and to the endpoint that
/// one replaced.
///
/// While contained, the lifeline rules decide the agent's connections to the server, so a connection opened then never reaches the
/// provider. Measured on edr-dev, releasing to settings that hand every flow to the provider cuts such a connection within seconds, and
/// with it the release command's own outcome on its way to the server. Kept as allow rules, those flows are not handed to the provider
/// and survive. They record no network_connect events.
///
/// The replaced endpoint is kept because a lifeline refresh is accepted before it is applied: one that failed to apply leaves the filter
/// allowing the endpoint the agent is still connected to. Older endpoints are not kept, since applying a later lifeline cut their
/// connections, and so the rules stay bounded however long a containment lasts. Everything is forgotten when a content filter starts:
/// its first settings carry no kept rules and a start cuts the connections they kept. The state is held in memory, not persisted.
struct ReleasedLifeline {
    private(set) var rules: [LifelineRule] = []
    /// latest is the server rules of the most recent containment update since the filter started or the host was last released, and
    /// replaced the different ones before it. A containment after a release or a start replaces the empty latest, so replaced needs no
    /// reset of its own.
    private var latest: [LifelineRule] = []
    private var replaced: [LifelineRule] = []

    /// accepted notes an accepted update. A containment or a lifeline refresh that moves the endpoint becomes the latest; a release keeps
    /// the latest and replaced endpoints. A release of a host that was not contained keeps what the last release kept.
    mutating func accepted(_ update: NetworkContainmentUpdate) {
        guard update.contained else {
            if !latest.isEmpty {
                rules = replaced.filter { !latest.contains($0) } + latest
                latest = []
            }
            return
        }
        let server = NetworkContainment.serverRules(for: update)
        if server != latest {
            replaced = latest
            latest = server
        }
    }

    /// filterStarting forgets the kept rules and starts over from the state the starting filter's first settings enforce.
    mutating func filterStarting(with state: NetworkContainmentUpdate?) {
        rules = []
        latest = []
        if let state {
            accepted(state)
        }
    }
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

    /// pending notes that the held state is about to be applied, because an update was accepted or a filter started: an earlier
    /// failure or confirmation concerned an earlier state or filter.
    mutating func pending() {
        applied = nil
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
                                 error: error, appliedAddresses: applied?.serverAddresses,
                                 appliedReachableVersion: applied?.reachableVersion)
    }
}
