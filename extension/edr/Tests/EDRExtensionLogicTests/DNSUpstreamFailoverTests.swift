// DNSUpstreamFailover tests: pin when a second resolver may be tried, and more importantly when it may not (issue #673).
//
// The proxy can no longer respond to a failing upstream by leaving the DNS path, because declining a flow terminates it.
// Trying another resolver is the honest alternative, but only where substituting one is semantically safe.

import Foundation
import Network
@testable import EDRExtensionLogic
import XCTest

final class DNSUpstreamFailoverTests: XCTestCase {
    private let systemServers = ["192.168.1.1", "192.168.1.2", "fd00::1"]

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-reports-forwarding-degradation-without-leaving-the-dns-path/a-query-to-a-system-resolver-is-retried-against-another-system-resolver
    func testFailsOverToTheNextSystemResolver() {
        // The client was using the system configuration, so any other configured resolver is a legitimate substitute:
        // it is exactly what mDNSResponder does when it rotates across them.
        XCTAssertEqual(DNSUpstreamFailover.nextServer(afterFailing: "192.168.1.1", systemServers: systemServers),
                       "192.168.1.2")
    }

    func testSkipsTheFailedServerWhereverItSitsInTheList() {
        // The failed server is not always first; the replacement must never be the server that just failed.
        XCTAssertEqual(DNSUpstreamFailover.nextServer(afterFailing: "192.168.1.2", systemServers: systemServers),
                       "192.168.1.1")
        XCTAssertEqual(DNSUpstreamFailover.nextServer(afterFailing: "fd00::1", systemServers: systemServers),
                       "192.168.1.1")
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-reports-forwarding-degradation-without-leaving-the-dns-path/a-query-to-a-client-chosen-resolver-is-not-retried-elsewhere
    func testNeverSubstitutesAResolverTheClientChose() {
        // `dig @8.8.8.8`, a container's own resolver, or a split-horizon corporate server reached deliberately. Answering
        // from a different resolver would answer a question the client did not ask, and split-horizon zones genuinely
        // resolve differently per resolver, so a "helpful" retry could hand back a wrong address for an internal name.
        XCTAssertNil(DNSUpstreamFailover.nextServer(afterFailing: "8.8.8.8", systemServers: systemServers))
        XCTAssertNil(DNSUpstreamFailover.nextServer(afterFailing: "10.0.0.53", systemServers: systemServers))
    }

    func testNoFailoverWhenItIsTheOnlyConfiguredResolver() {
        // Retrying the same server is not a failover, it is a duplicate. The per-attempt deadline already bounds the
        // wait; the client's own resolver will retry if it wants to.
        XCTAssertNil(DNSUpstreamFailover.nextServer(afterFailing: "192.168.1.1", systemServers: ["192.168.1.1"]))
    }

    func testNoFailoverWithoutASystemConfiguration() {
        // An empty system list cannot make a query "system-configured", so there is nothing safe to substitute.
        XCTAssertNil(DNSUpstreamFailover.nextServer(afterFailing: "192.168.1.1", systemServers: []))
    }

    func testRendersEndpointAddressesForComparison() {
        XCTAssertEqual(DNSUpstreamFailover.address(of: .hostPort(host: "192.168.1.1", port: 53)), "192.168.1.1")
        XCTAssertEqual(DNSUpstreamFailover.address(of: .hostPort(host: "fd00::1", port: 53)), "fd00::1")
        // A hostname resolver target renders as its name rather than being dropped.
        XCTAssertEqual(DNSUpstreamFailover.address(of: .hostPort(host: "dns.example.com", port: 53)),
                       "dns.example.com")
    }

    func testStripsTheInterfaceScopeFromLinkLocalAddresses() {
        // A flow to a link-local resolver renders with its scope (`fe80::1%en0`) while the system configuration lists it
        // unscoped, so without stripping the two would never compare equal and a link-local resolver could never be
        // recognised as system-configured.
        let scoped = NWEndpoint.hostPort(host: NWEndpoint.Host("fe80::1%en0"), port: 53)
        XCTAssertEqual(DNSUpstreamFailover.address(of: scoped), "fe80::1")
        XCTAssertEqual(DNSUpstreamFailover.nextServer(afterFailing: DNSUpstreamFailover.address(of: scoped),
                                                      systemServers: ["fe80::1", "192.168.1.1"]),
                       "192.168.1.1")
    }

    func testPreservesANonStandardResolverPort() {
        // A resolver on a non-standard port must keep it on the failover attempt, or the retry goes somewhere nothing
        // is listening.
        XCTAssertEqual(DNSUpstreamFailover.port(of: .hostPort(host: "192.168.1.1", port: 5353)), 5353)
        XCTAssertEqual(DNSUpstreamFailover.port(of: .hostPort(host: "192.168.1.1", port: 53)), 53)
    }

    func testMatchesAddressesByValueNotByString() {
        // The failed server is rendered from an NWEndpoint on the flow; the candidates come from the dynamic store.
        // The two need not spell an address the same way, and a textual compare would fail closed, silently disabling
        // the failover for a host whose resolver is written in the expanded form.
        XCTAssertTrue(DNSUpstreamFailover.sameAddress("fd00::1", "fd00:0:0:0:0:0:0:1"))
        XCTAssertTrue(DNSUpstreamFailover.sameAddress("fe80::1%en0", "fe80::1"))
        XCTAssertFalse(DNSUpstreamFailover.sameAddress("fd00::1", "fd00::2"))
        XCTAssertTrue(DNSUpstreamFailover.sameAddress("192.168.1.1", "192.168.1.1"))
        XCTAssertFalse(DNSUpstreamFailover.sameAddress("192.168.1.1", "192.168.1.2"))
    }

    func testExpandedIPv6SystemEntryStillCountsAsSystemConfigured() {
        // End to end through the selection rule: the flow says `fd00::1`, the system configuration says the expanded
        // form. Before value comparison this returned nil, i.e. no failover at all.
        XCTAssertEqual(DNSUpstreamFailover.nextServer(afterFailing: "fd00::1",
                                                      systemServers: ["fd00:0:0:0:0:0:0:1", "192.168.1.1"]),
                       "192.168.1.1")
    }

    func testUnknownFailedServerYieldsNoFailover() {
        // A flow whose target we could not render must not silently pick the first system resolver: that would redirect
        // a query we cannot even attribute to a server the client may never have used.
        XCTAssertNil(DNSUpstreamFailover.nextServer(afterFailing: nil, systemServers: systemServers))
        XCTAssertNil(DNSUpstreamFailover.nextServer(afterFailing: "", systemServers: systemServers))
    }
}
