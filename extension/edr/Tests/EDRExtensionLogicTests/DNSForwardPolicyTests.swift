// DNSForwardPolicy tests: pin how a claimed DNS flow is routed so our forward can never re-enter the tunnel of a
// provider that may be blocked waiting on our answer (issue #656). The entitlement probe is injected, so the routing
// matrix is exercised without a live flow or a real SecCode walk.
//
// Note what is NOT tested here, because it is not what the code does: declining another provider's flows. Returning
// false from handleNewFlow fails CLOSED on macOS (measured: with every flow declined, dig, dscacheutil and ping all
// failed to resolve, while the same queries succeeded with the proxy configuration disabled), so every flow stays
// claimed and only the forward's routing changes.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class DNSForwardPolicyTests: XCTestCase {
    private let ownID = "com.fleetdm.edr.networkextension"

    private func policy() -> DNSForwardPolicy {
        DNSForwardPolicy(ownSigningIdentifier: ownID)
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-forwards-away-from-another-provider-s-tunnel/a-forward-for-another-network-extension-provider-avoids-tunnel-interfaces
    func testAnotherProviderAvoidsTunnelEgress() {
        // The 2026-07-27 shape: a tunnel provider's own resolver traffic reaches us. Forwarding it over the default route
        // sends it back into that provider's tunnel, which cannot answer until we forward. Keeping the forward off tunnel
        // interfaces breaks the cycle while still resolving the query.
        let routing = policy().routing(sourceSigningIdentifier: "io.tailscale.ipn.macos.network-extension",
                                       sourceIsNetworkExtensionProvider: true)
        XCTAssertEqual(routing, .avoidTunnelEgress)
    }

    // spec:extension-network-response/dns-proxy-forwards-away-from-another-provider-s-tunnel/an-ordinary-flow-honours-the-interface-the-client-bound
    func testOrdinaryApplicationHonoursBoundInterface() {
        // Ordinary lookups are the monitoring tap's whole purpose, and mDNSResponder carries most host DNS without
        // holding the entitlement. Those keep normal routing, pinned to whatever the client bound.
        let routing = policy().routing(sourceSigningIdentifier: "com.apple.mDNSResponder",
                                       sourceIsNetworkExtensionProvider: false)
        XCTAssertEqual(routing, .honourBoundInterface)
    }

    func testOwnProviderTakesOrdinaryRoutingDespiteHoldingTheEntitlement() {
        // Our own provider holds content-filter-provider-systemextension + dns-proxy-systemextension, so the probe
        // answers true for us too. The system already keeps our outbound connections out of the proxy chain, so there is
        // no loop to break and no reason to deny ourselves a tunnel route.
        XCTAssertEqual(policy().routing(sourceSigningIdentifier: ownID, sourceIsNetworkExtensionProvider: true),
                       .honourBoundInterface)
    }

    func testProbeIsNotConsultedForOwnIdentifier() {
        // The probe is a SecCode walk on the DNS hot path, so it must be skipped for our own identifier. The autoclosure
        // parameter makes that possible; this asserts the laziness rather than trusting it.
        var probeCalls = 0
        let routing = policy().routing(sourceSigningIdentifier: ownID,
                                       sourceIsNetworkExtensionProvider: { probeCalls += 1; return true }())
        XCTAssertEqual(routing, .honourBoundInterface)
        XCTAssertEqual(probeCalls, 0, "the entitlement probe must not run for our own identifier")
    }

    func testProbeDecidesForEveryOtherIdentifier() {
        // Same identifier, opposite probe answers: proves the probe (not the string) is what decides for a third party.
        let peer = "com.wireguard.macos.network-extension"
        XCTAssertEqual(policy().routing(sourceSigningIdentifier: peer, sourceIsNetworkExtensionProvider: true),
                       .avoidTunnelEgress)
        XCTAssertEqual(policy().routing(sourceSigningIdentifier: peer, sourceIsNetworkExtensionProvider: false),
                       .honourBoundInterface)
    }

    func testEmptySigningIdentifierIsDecidedByTheProbe() {
        // A flow can arrive with an empty signing identifier. It must not accidentally match our own identifier and
        // thereby skip the probe.
        XCTAssertEqual(policy().routing(sourceSigningIdentifier: "", sourceIsNetworkExtensionProvider: true),
                       .avoidTunnelEgress)
    }

    func testEmptyOwnIdentifierMatchesNothing() {
        // The provider builds this from `Bundle.main.bundleIdentifier ?? ""`. That is documented to be present for a
        // system extension, but a misconfigured bundle can leave it nil, and an empty own identifier must then match
        // NOTHING rather than matching every unattributed flow: the latter would grant tunnel egress to exactly the
        // flows least able to justify it, silently and only on a misconfigured host.
        let degraded = DNSForwardPolicy(ownSigningIdentifier: "")
        var probeCalls = 0
        let routing = degraded.routing(sourceSigningIdentifier: "",
                                       sourceIsNetworkExtensionProvider: { probeCalls += 1; return true }())
        XCTAssertEqual(routing, .avoidTunnelEgress)
        XCTAssertEqual(probeCalls, 1, "the probe must decide when our own identifier is unknown")
        // A named source is likewise decided by the probe, not by a spurious match against the empty own identifier.
        XCTAssertEqual(degraded.routing(sourceSigningIdentifier: "com.example.app",
                                        sourceIsNetworkExtensionProvider: false), .honourBoundInterface)
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-forwards-away-from-another-provider-s-tunnel/tunnel-avoiding-forwards-do-not-drive-the-health-watchdog
    func testOnlyOrdinaryRoutingFeedsTheHealthWatchdog() {
        // A tunnel-avoiding forward is denied the tunnel by design, so on a full-tunnel host it fails by construction.
        // Counting those failures would push the watchdog toward a bypass, and a bypass is a host-wide DNS outage rather
        // than the fail-open it is named for, so they must stay out of the accounting.
        XCTAssertTrue(DNSForwardPolicy.Routing.honourBoundInterface.feedsHealthWatchdog)
        XCTAssertFalse(DNSForwardPolicy.Routing.avoidTunnelEgress.feedsHealthWatchdog)
    }
}
