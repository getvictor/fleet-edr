import Foundation
import Network
import os

/// InterfaceSnapshot keeps a name-keyed view of the host's currently available network interfaces so an upstream DNS
/// forward can be pinned to the interface the client bound its flow to.
///
/// Why pinning matters (issue #656): `NWConnection(to:using:.udp)` with default parameters follows the system default
/// route. When a tunnel provider owns that route, a forward we make on behalf of a flow the client had bound to a
/// different interface is silently re-routed into the tunnel. The client chose an interface; honouring that choice keeps
/// our forward on the same path the query was already travelling and removes one way for the proxy to end up inside
/// another provider's resolution path.
///
/// The bridge is by NAME on purpose. `NEAppProxyFlow.networkInterface` vends an `nw_interface_t`, while
/// `NWParameters.requiredInterface` wants an `NWInterface`, and the Swift overlay exposes no initialiser between the two.
/// `NWPathMonitor` is the supported way to enumerate `NWInterface` values, and interface names (`en0`, `utun4`) are unique
/// on a live system, so matching `nw_interface_get_name` against that set is the available path.
///
/// Concurrency: `handleNewFlow` runs concurrently while the monitor updates on its own queue, so the map is guarded by an
/// unfair lock around a constant-time dictionary read, matching the locking shape used elsewhere in the extensions.
final class InterfaceSnapshot {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "com.fleetdm.edr.networkextension.interfaces")
    private let byName = OSAllocatedUnfairLock<[String: NWInterface]>(initialState: [:])

    /// start begins watching for path changes. Called from startProxy so the first claimed flow already has a snapshot;
    /// until the first update lands `interface(named:)` returns nil and the forward simply uses default routing, which is
    /// the pre-existing behaviour.
    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            self?.update(with: path.availableInterfaces)
        }
        monitor.start(queue: queue)
    }

    /// stop releases the path monitor. Called from `stopProxy` so the monitor and its dispatch queue do not outlive the
    /// proxy's active lifetime: `stopProxy` is invoked on configuration changes, not only at process exit, so a monitor
    /// left running would accumulate one per start/stop cycle.
    func stop() {
        monitor.cancel()
    }

    /// update replaces the snapshot. Internal rather than private so tests can drive it without a live path monitor.
    func update(with interfaces: [NWInterface]) {
        // uniquingKeysWith keeps the first entry: names are unique on a live system, so a duplicate would be a platform
        // surprise rather than something to merge, and keeping one is better than trapping on the DNS path.
        let mapped = Dictionary(interfaces.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
        byName.withLock { $0 = mapped }
    }

    /// interface(named:) resolves a live `NWInterface` by name, or nil when the name is unknown to the current path.
    func interface(named name: String) -> NWInterface? {
        byName.withLock { $0[name] }
    }

    /// udpParameters builds forward parameters for a routing decision. `boundInterface` is the interface the client bound
    /// its flow to, when it bound one.
    static func udpParameters(routing: DNSForwardPolicy.Routing, boundInterface: NWInterface?) -> NWParameters {
        apply(routing: routing, boundInterface: boundInterface, to: NWParameters.udp)
    }

    /// tcpParameters is the TCP counterpart, for the rare TCP DNS path.
    static func tcpParameters(routing: DNSForwardPolicy.Routing, boundInterface: NWInterface?) -> NWParameters {
        apply(routing: routing, boundInterface: boundInterface, to: NWParameters.tcp)
    }

    /// apply expresses the routing decision in Network framework terms. Shared by both transports so the two can never
    /// drift, which would be invisible until a TCP DNS query looped where a UDP one did not.
    ///
    /// `avoidTunnelEgress` prohibits `.other`, which is how a `utun` interface classifies (verified against a live host:
    /// `en0` reports `.wifi`, `en7` `.wiredEthernet`, and `utun6` `.other`). Prohibiting the type rather than naming
    /// interfaces keeps this correct as tunnels come and go, which they do every time a VPN connects.
    private static func apply(routing: DNSForwardPolicy.Routing, boundInterface: NWInterface?,
                              to parameters: NWParameters) -> NWParameters {
        switch routing {
        case .honourBoundInterface:
            parameters.requiredInterface = boundInterface
        case .avoidTunnelEgress:
            parameters.prohibitedInterfaceTypes = [.other]
        }
        return parameters
    }
}
