import XCTest
@testable import EDRExtensionLogic

/// The operator-chosen destinations a contained host may still reach (issue #1059): how a document carries them, how they become
/// filter rules, and the ordering rule that decides whether a changed set reaches the host at all.
final class NetworkContainmentReachableTests: XCTestCase {
    private func payload(_ json: String) -> Data {
        Data(json.utf8)
    }

    /// entry builds one operator-chosen destination the way a document carries it.
    private func entry(_ cidr: String, port: Int? = nil, transport: String? = nil) -> NetworkContainment.ReachableEntry {
        NetworkContainment.ReachableEntry(cidr: cidr, port: port, transport: transport)
    }

    /// The trap this whole delivery path turns on. Changing the reachable set does NOT change the host's containment version or
    /// epoch, so the command that carries the new set arrives at the same order as the one the extension already holds. Without the
    /// set counting as part of the lifeline, `accept` would take that update for neither newer nor a refresh, discard it, and the
    /// command would still COMPLETE: the operator would see success and nothing would have changed.
    ///
    /// spec:extension-network-response/containment-state-is-persisted-and-ordered/a-lifeline-refresh-at-the-same-version-is-accepted
    func testAChangedReachableSetIsALifelineRefresh() {
        let current = NetworkContainmentUpdate(
            version: 5, epoch: 100, contained: true, serverPort: 8443, serverAddresses: ["203.0.113.7"],
            reachableVersion: 2, reachable: [entry("192.0.2.7/32", port: 443, transport: "tcp")]
        )
        let newer = NetworkContainmentUpdate(
            version: 5, epoch: 100, contained: true, serverPort: 8443, serverAddresses: ["203.0.113.7"],
            reachableVersion: 3, reachable: [entry("198.51.100.5/32", port: nil, transport: nil)]
        )
        XCTAssertTrue(newer.refreshesLifeline(current), "the same containment with a different set is a lifeline that moved")
        XCTAssertFalse(newer.supersedes(current), "and it is NOT newer, which is exactly why the refresh check has to see it")

        let same = NetworkContainmentUpdate(
            version: 5, epoch: 100, contained: true, serverPort: 8443, serverAddresses: ["203.0.113.7"],
            reachableVersion: 2, reachable: [entry("192.0.2.7/32", port: 443, transport: "tcp")]
        )
        XCTAssertFalse(same.refreshesLifeline(current), "the same set is not a refresh")
    }

    /// A document from before this shipped has no reachable keys at all. It must still decode: a host that upgrades while contained
    /// loads its own persisted state through this path, and refusing it would bring the host up UNCONTAINED.
    func testADocumentWithoutAReachableSetStillDecodes() {
        let update = NetworkContainment.decode(payload("""
        {"version":4,"epoch":90,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]}}
        """))
        XCTAssertNotNil(update)
        XCTAssertEqual(update?.reachableVersion, 0, "no set is version 0, which is the set every deployment starts with")
        XCTAssertEqual(update?.reachable, [])
    }

    func testDecodeReadsTheReachableSet() {
        let update = NetworkContainment.decode(payload("""
        {"version":4,"epoch":90,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]},
         "reachableVersion":7,"reachable":[{"cidr":"192.0.2.7/32","port":443,"transport":"tcp"},{"cidr":"10.0.0.0/8"}]}
        """))
        XCTAssertEqual(update?.reachableVersion, 7)
        XCTAssertEqual(update?.reachable.count, 2)
        XCTAssertEqual(update?.reachable.first?.cidr, "192.0.2.7/32")
    }

    func testReachableRulesMapEachDestination() {
        let rules = NetworkContainment.reachableRules(for: [
            entry("192.0.2.7/32", port: 443, transport: "tcp"),
            entry("10.0.0.0/8", port: nil, transport: nil),
            entry("2001:db8::1/128", port: 53, transport: "udp")
        ])
        // One rule for a named transport, two for an entry that named none: an operator who wrote only an address meant the
        // destination, not a protocol.
        XCTAssertEqual(rules.count, 4)
        XCTAssertEqual(rules[0], LifelineRule(address: "192.0.2.7", prefix: 32, port: 443, transport: .tcp, direction: .outbound))
        XCTAssertEqual(rules[1], LifelineRule(address: "10.0.0.0", prefix: 8, port: 0, transport: .tcp, direction: .outbound))
        XCTAssertEqual(rules[2], LifelineRule(address: "10.0.0.0", prefix: 8, port: 0, transport: .udp, direction: .outbound))
        XCTAssertEqual(rules[3], LifelineRule(address: "2001:db8::1", prefix: 128, port: 53, transport: .udp, direction: .outbound))
        XCTAssertTrue(rules.allSatisfy { $0.direction == .outbound }, "this opens what the host may reach, never what may reach it")
    }

    /// An entry the extension cannot express is dropped rather than costing the host its containment. The server validated these, so
    /// a drop means the two disagree, and the direction to fail in is one allowance missing rather than a host left uncontained.
    func testAnUnusableReachableEntryIsDroppedNotFatal() {
        let rules = NetworkContainment.reachableRules(for: [
            entry("not-an-address", port: nil, transport: nil),
            entry("192.0.2.7/33", port: nil, transport: nil),
            entry("192.0.2.9/32", port: 70000, transport: "tcp"),
            entry("192.0.2.10/32", port: 443, transport: "sctp"),
            entry("192.0.2.11/32", port: 443, transport: "tcp")
        ])
        XCTAssertEqual(rules.count, 1, "only the usable entry survives")
        XCTAssertEqual(rules[0].address, "192.0.2.11")
    }

    func testReachableRulesAreCapped() {
        let many = (1...(NetworkContainment.maxReachable + 10)).map {
            entry("192.0.2.\($0 % 250 + 1)/32", port: 443, transport: "tcp")
        }
        XCTAssertEqual(NetworkContainment.reachableRules(for: many).count, NetworkContainment.maxReachable)
    }

    /// The whole lifeline, with the allowances beside the pieces that were always there. What matters is that adding them took
    /// nothing away: a contained host still reaches its server, still gets DHCP, and still resolves through its own resolvers.
    func testTheLifelineKeepsItsOwnRulesAndAddsTheAllowances() {
        let update = NetworkContainmentUpdate(
            version: 5, epoch: 100, contained: true, serverPort: 8443, serverAddresses: ["203.0.113.7"],
            reachableVersion: 3, reachable: [entry("192.0.2.7/32", port: 443, transport: "tcp")]
        )
        let withSet = NetworkContainment.lifeline(for: update, resolvers: ["198.51.100.1"])
        let without = NetworkContainment.lifeline(
            for: NetworkContainmentUpdate(version: 5, epoch: 100, contained: true, serverPort: 8443,
                                          serverAddresses: ["203.0.113.7"]),
            resolvers: ["198.51.100.1"]
        )
        XCTAssertEqual(withSet.count, without.count + 1)
        XCTAssertTrue(without.allSatisfy { withSet.contains($0) }, "nothing the lifeline already allowed was displaced")
        XCTAssertTrue(withSet.contains(LifelineRule(address: "192.0.2.7", prefix: 32, port: 443, transport: .tcp,
                                                    direction: .outbound)))
    }

    /// A host that is not contained has no lifeline at all, so it has no allowances either: they describe a restriction that is not
    /// in force.
    func testAReleasedHostHasNoReachableRules() {
        let released = NetworkContainmentUpdate(
            version: 6, epoch: 110, contained: false, serverPort: 0, serverAddresses: [],
            reachableVersion: 3, reachable: [entry("192.0.2.7/32", port: 443, transport: "tcp")]
        )
        XCTAssertTrue(NetworkContainment.lifeline(for: released, resolvers: ["198.51.100.1"]).isEmpty)
    }

    /// A set version only ever increases, so an update naming a LOWER one was built before the change and delayed on its way here.
    /// Accepting it would roll the host's allowances back to a set an operator has already replaced, and nothing upstream serializes
    /// a refresh against a command, so the delayed document is a real arrival order rather than a hypothetical one.
    func testAnOlderReachableSetDoesNotRefresh() {
        let current = NetworkContainmentUpdate(
            version: 5, epoch: 100, contained: true, serverPort: 8443, serverAddresses: ["203.0.113.7"],
            reachableVersion: 3, reachable: [entry("198.51.100.5/32")]
        )
        let stale = NetworkContainmentUpdate(
            version: 5, epoch: 100, contained: true, serverPort: 8443, serverAddresses: ["203.0.113.7"],
            reachableVersion: 2, reachable: [entry("192.0.2.7/32")]
        )
        XCTAssertFalse(stale.refreshesLifeline(current), "an older set is a document that lost a race, not a change")

        // A server address that moved is still a refresh, whatever the set version says, because that half is what it always was.
        let moved = NetworkContainmentUpdate(
            version: 5, epoch: 100, contained: true, serverPort: 8443, serverAddresses: ["203.0.113.9"],
            reachableVersion: 3, reachable: [entry("198.51.100.5/32")]
        )
        XCTAssertTrue(moved.refreshesLifeline(current))
    }
}
