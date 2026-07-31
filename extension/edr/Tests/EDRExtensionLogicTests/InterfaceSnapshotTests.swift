// InterfaceSnapshot tests: pin the name-keyed lookup and the routing-to-NWParameters translation that keeps an upstream
// DNS forward either on the interface the client bound, or off tunnel interfaces entirely (issue #656).
//
// NWInterface has no public initialiser, so the populated-snapshot cases source real interfaces from an NWPathMonitor.
// Every macOS host has at least lo0, but the test skips rather than fails if the path reports none, so a sandboxed runner
// with no interfaces cannot produce a false red.

import Foundation
import Network
@testable import EDRExtensionLogic
import XCTest

final class InterfaceSnapshotTests: XCTestCase {
    /// Resolve the host's live interfaces once, via the same NWPathMonitor the production type uses.
    private func liveInterfaces(timeout: TimeInterval = 5) throws -> [NWInterface] {
        let monitor = NWPathMonitor()
        let settled = expectation(description: "path update")
        var found: [NWInterface] = []
        monitor.pathUpdateHandler = { path in
            guard found.isEmpty else { return }
            found = path.availableInterfaces
            settled.fulfill()
        }
        monitor.start(queue: DispatchQueue(label: "InterfaceSnapshotTests"))
        defer { monitor.cancel() }
        wait(for: [settled], timeout: timeout)
        try XCTSkipIf(found.isEmpty, "no network interfaces visible to this runner")
        return found
    }

    func testUnknownNameResolvesToNil() {
        // A fresh snapshot knows nothing, and an unresolvable name must yield nil rather than trapping: the forward then
        // falls back to default routing, which is the pre-existing behaviour.
        let snapshot = InterfaceSnapshot()
        XCTAssertNil(snapshot.interface(named: "utun99"))
    }

    func testResolvesInterfaceByName() throws {
        let interfaces = try liveInterfaces()
        let snapshot = InterfaceSnapshot()
        snapshot.update(with: interfaces)

        let target = try XCTUnwrap(interfaces.first)
        let resolved = try XCTUnwrap(snapshot.interface(named: target.name),
                                     "a name present in the snapshot must resolve")
        XCTAssertEqual(resolved.name, target.name)
        // A name absent from the snapshot still resolves to nil, so the lookup is a real map and not a catch-all.
        XCTAssertNil(snapshot.interface(named: target.name + "-absent"))
    }

    func testUpdateReplacesThePreviousSnapshot() throws {
        let interfaces = try liveInterfaces()
        let snapshot = InterfaceSnapshot()
        snapshot.update(with: interfaces)
        let name = try XCTUnwrap(interfaces.first).name
        XCTAssertNotNil(snapshot.interface(named: name))

        // An interface disappearing from the path (a tunnel going down) must drop out of the snapshot, not linger and
        // pin forwards to a dead interface.
        snapshot.update(with: [])
        XCTAssertNil(snapshot.interface(named: name))
    }

    func testUnboundOrdinaryFlowKeepsDefaultRouting() {
        // An unbound flow expresses no interface preference, so its forward keeps default routing.
        for parameters in [InterfaceSnapshot.udpParameters(routing: .honourBoundInterface, boundInterface: nil),
                           InterfaceSnapshot.tcpParameters(routing: .honourBoundInterface, boundInterface: nil)] {
            XCTAssertNil(parameters.requiredInterface)
            XCTAssertTrue(parameters.prohibitedInterfaceTypes?.isEmpty ?? true)
        }
    }

    func testTunnelAvoidingRoutingProhibitsTunnelInterfaces() {
        // This is the actual deadlock fix: a forward for another provider's flow must never leave over a tunnel, because
        // that tunnel's provider may be the thing blocked waiting for our answer. utun classifies as .other (verified on a
        // live host: en0 .wifi, en7 .wiredEthernet, utun6 .other).
        for parameters in [InterfaceSnapshot.udpParameters(routing: .avoidTunnelEgress, boundInterface: nil),
                           InterfaceSnapshot.tcpParameters(routing: .avoidTunnelEgress, boundInterface: nil)] {
            XCTAssertEqual(parameters.prohibitedInterfaceTypes, [.other])
            XCTAssertNil(parameters.requiredInterface)
        }
    }

    func testOrdinaryRoutingCarriesTheBoundInterface() throws {
        let target = try XCTUnwrap(try liveInterfaces().first)
        // Fixes the silent re-route: the forward leaves on the interface the client chose rather than following the
        // system default route into whichever tunnel currently owns it.
        XCTAssertEqual(InterfaceSnapshot.udpParameters(routing: .honourBoundInterface,
                                                       boundInterface: target).requiredInterface?.name, target.name)
        XCTAssertEqual(InterfaceSnapshot.tcpParameters(routing: .honourBoundInterface,
                                                       boundInterface: target).requiredInterface?.name, target.name)
    }

    func testTunnelAvoidingRoutingIgnoresTheBoundInterface() throws {
        let target = try XCTUnwrap(try liveInterfaces().first)
        // Deliberate: the interface the provider bound may itself BE the tunnel we must stay off, so a tunnel-avoiding
        // forward must not be pinned to it.
        let parameters = InterfaceSnapshot.udpParameters(routing: .avoidTunnelEgress, boundInterface: target)
        XCTAssertNil(parameters.requiredInterface)
        XCTAssertEqual(parameters.prohibitedInterfaceTypes, [.other])
    }

    func testParametersUseTheExpectedTransport() {
        // Guards against a copy-paste swap between the two builders: a TCP DNS flow forwarded over UDP (or the reverse)
        // would corrupt the 2-byte-length-prefixed TCP wire format.
        XCTAssertTrue(InterfaceSnapshot.udpParameters(routing: .honourBoundInterface, boundInterface: nil)
            .defaultProtocolStack.transportProtocol is NWProtocolUDP.Options)
        XCTAssertTrue(InterfaceSnapshot.tcpParameters(routing: .honourBoundInterface, boundInterface: nil)
            .defaultProtocolStack.transportProtocol is NWProtocolTCP.Options)
    }
}
