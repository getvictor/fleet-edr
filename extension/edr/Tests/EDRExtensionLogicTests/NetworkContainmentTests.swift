import Foundation
@testable import EDRExtensionLogic
import XCTest

/// Tests for host network containment's pure half (#948): decoding and ordering containment updates, the lifeline a contained host
/// keeps, the persisted store, and the status wire shape. Applying the rules as content-filter settings, and what the operating system
/// then does with established connections and provider restarts, is exercised on edr-dev, because NetworkContainmentController imports
/// NetworkExtension and is outside this target.
final class NetworkContainmentTests: XCTestCase {
    private func payload(_ json: String) -> Data {
        Data(json.utf8)
    }

    private func contained(version: Int64 = 3, epoch: Int64 = 100, port: UInt16 = 8443,
                           addresses: [String] = ["203.0.113.7"]) -> NetworkContainmentUpdate {
        NetworkContainmentUpdate(version: version, epoch: epoch, contained: true, serverPort: port, serverAddresses: addresses)
    }

    // MARK: decode

    func testDecodeReadsAContainment() {
        let update = NetworkContainment.decode(payload("""
        {"version": 3, "epoch": 100, "contained": true, "server": {"port": 8443, "addresses": ["203.0.113.7", "2001:db8::7"]}}
        """))
        XCTAssertEqual(update, contained(addresses: ["203.0.113.7", "2001:db8::7"]))
    }

    func testDecodeReadsAReleaseWithoutAServer() {
        let update = NetworkContainment.decode(payload(#"{"version": 4, "contained": false}"#))
        XCTAssertEqual(update, NetworkContainmentUpdate(version: 4, epoch: 0, contained: false, serverPort: 0, serverAddresses: []))
    }

    // spec:extension-network-response/containment-state-is-persisted-and-ordered/a-containment-without-a-usable-lifeline-is-refused
    func testDecodeRefusesAContainmentWithoutAUsableLifeline() {
        let tooMany = (1...(NetworkContainment.maxServerAddresses + 1)).map { "\"203.0.113.\($0)\"" }.joined(separator: ",")
        let refused: [(String, String)] = [
            ("no server", #"{"version":1,"contained":true}"#),
            ("no addresses", #"{"version":1,"contained":true,"server":{"port":443,"addresses":[]}}"#),
            ("a host name", #"{"version":1,"contained":true,"server":{"port":443,"addresses":["edr.example.com"]}}"#),
            ("one bad address among good ones",
             #"{"version":1,"contained":true,"server":{"port":443,"addresses":["203.0.113.7","nope"]}}"#),
            ("the IPv4 unspecified address", #"{"version":1,"contained":true,"server":{"port":443,"addresses":["0.0.0.0"]}}"#),
            ("an address with an embedded NUL",
             #"{"version":1,"contained":true,"server":{"port":443,"addresses":["203.0.113.7\u0000x"]}}"#),
            ("the IPv6 unspecified address", #"{"version":1,"contained":true,"server":{"port":443,"addresses":["::"]}}"#),
            ("port 0", #"{"version":1,"contained":true,"server":{"port":0,"addresses":["203.0.113.7"]}}"#),
            ("port above 65535", #"{"version":1,"contained":true,"server":{"port":65536,"addresses":["203.0.113.7"]}}"#),
            ("too many addresses", #"{"version":1,"contained":true,"server":{"port":443,"addresses":[\#(tooMany)]}}"#),
            ("not a containment document", #"{"paths":[]}"#),
            ("not JSON", "contain")
        ]
        for (why, json) in refused {
            XCTAssertNil(NetworkContainment.decode(payload(json)), why)
        }
        let atTheCap = (1...NetworkContainment.maxServerAddresses).map { "\"203.0.113.\($0)\"" }.joined(separator: ",")
        XCTAssertNotNil(NetworkContainment.decode(payload("""
        {"version":1,"contained":true,"server":{"port":65535,"addresses":[\(atTheCap)]}}
        """)), "the limits themselves are usable")
    }

    // MARK: ordering

    // spec:extension-network-response/containment-state-is-persisted-and-ordered/an-older-update-is-refused
    func testSupersedesOrdersByEpochThenVersion() {
        let current = contained(version: 5, epoch: 100)
        XCTAssertTrue(contained(version: 1, epoch: 101).supersedes(current), "a later epoch wins over a lower version")
        XCTAssertTrue(contained(version: 6, epoch: 100).supersedes(current))
        XCTAssertFalse(contained(version: 5, epoch: 100).supersedes(current), "the same update is not newer")
        XCTAssertFalse(contained(version: 4, epoch: 100).supersedes(current))
        XCTAssertFalse(contained(version: 9, epoch: 99).supersedes(current), "an earlier epoch loses whatever its version")
        XCTAssertTrue(contained().supersedes(nil))
    }

    // spec:extension-network-response/containment-state-is-persisted-and-ordered/a-lifeline-refresh-at-the-same-version-is-accepted
    func testRefreshesLifelineOnlyAtTheSameVersionWhenTheEndpointMoved() {
        let current = contained(version: 5, epoch: 100, port: 8443, addresses: ["203.0.113.7"])
        XCTAssertTrue(contained(version: 5, epoch: 100, addresses: ["203.0.113.8"]).refreshesLifeline(current))
        XCTAssertTrue(contained(version: 5, epoch: 100, port: 443).refreshesLifeline(current))
        XCTAssertFalse(contained(version: 5, epoch: 100).refreshesLifeline(current), "nothing moved")
        XCTAssertFalse(contained(version: 4, epoch: 100, addresses: ["203.0.113.8"]).refreshesLifeline(current), "older")
        let release = NetworkContainmentUpdate(version: 5, epoch: 100, contained: false, serverPort: 0, serverAddresses: [])
        XCTAssertFalse(release.refreshesLifeline(current), "a release at the same version is not a refresh")
        XCTAssertFalse(contained().refreshesLifeline(nil))
    }

    // MARK: resolver lifeline

    // The settings a filter starts with are built from the resolvers known at that moment, and that snapshot goes stale when the read
    // warming it lands afterwards, or when the list moves while no filter is running. Nothing else asks for an apply in either case,
    // so the comparison is what keeps a contained host's DNS from being left behind (issue #1069).
    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/resolvers-that-move-under-a-contained-host-apply
    func testResolverLifelineAsksForAnApplyWhenTheListMoved() {
        var lifeline = ResolverLifeline()
        XCTAssertNil(lifeline.applied)
        // Before anything is applied there is nothing to compare against, and an empty list is a real answer rather than an unknown.
        XCTAssertTrue(lifeline.needsApply(for: []))

        lifeline.recordApplied([])
        XCTAssertFalse(lifeline.needsApply(for: []), "settings that name no resolver need no re-apply while none is known")
        XCTAssertTrue(lifeline.needsApply(for: ["198.51.100.1"]), "a read landing after the filter started")

        lifeline.recordApplied(["198.51.100.1"])
        XCTAssertFalse(lifeline.needsApply(for: ["198.51.100.1"]))
        XCTAssertTrue(lifeline.needsApply(for: ["198.51.100.9"]), "the list moved while the filter was down")
    }

    // MARK: lifeline

    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/a-contained-host-keeps-only-the-lifeline
    func testLifelineIsTheServerDHCPAndTheConfiguredResolvers() {
        let rules = NetworkContainment.lifeline(for: contained(port: 8443, addresses: ["203.0.113.7", "2001:db8::7"]),
                                                resolvers: ["198.51.100.1", "2001:db8::53"])
        XCTAssertEqual(rules, [
            LifelineRule(address: "203.0.113.7", prefix: 32, port: 8443, transport: .tcp, direction: .outbound),
            LifelineRule(address: "2001:db8::7", prefix: 128, port: 8443, transport: .tcp, direction: .outbound),
            LifelineRule(address: "0.0.0.0", prefix: 0, port: 67, localPort: 68, transport: .udp, direction: .any),
            LifelineRule(address: "::", prefix: 0, port: 547, localPort: 546, transport: .udp, direction: .any),
            LifelineRule(address: "198.51.100.1", prefix: 32, port: 53, transport: .udp, direction: .outbound),
            LifelineRule(address: "198.51.100.1", prefix: 32, port: 53, transport: .tcp, direction: .outbound),
            LifelineRule(address: "2001:db8::53", prefix: 128, port: 53, transport: .udp, direction: .outbound),
            LifelineRule(address: "2001:db8::53", prefix: 128, port: 53, transport: .tcp, direction: .outbound)
        ])
    }

    // The hole this closes (issue #1069): the restriction on which names a contained host may resolve lives in the DNS proxy, and a
    // host can be contained with the proxy off, stopped or wedged. DNS to an address of the caller's choosing is a way out of the
    // host, so the lifeline names the resolvers instead of allowing port 53 to anywhere.
    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/contained-dns-reaches-only-the-configured-resolvers
    func testLifelineAllowsNoDNSToAnAddressThatIsNotAConfiguredResolver() {
        let rules = NetworkContainment.lifeline(for: contained(port: 8443, addresses: ["203.0.113.7"]), resolvers: ["198.51.100.1"])
        let dns = rules.filter { $0.port == 53 }
        XCTAssertEqual(dns.map(\.address), ["198.51.100.1", "198.51.100.1"])
        XCTAssertTrue(dns.allSatisfy { $0.prefix == 32 && $0.direction == .outbound })
        XCTAssertFalse(rules.contains { $0.port == 53 && ($0.address == "0.0.0.0" || $0.address == "::") })
    }

    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/contained-dns-reaches-only-the-configured-resolvers
    func testLifelineAllowsNoDNSWhenNoResolverIsKnown() {
        let rules = NetworkContainment.lifeline(for: contained(port: 8443, addresses: ["203.0.113.7"]), resolvers: [])
        XCTAssertFalse(rules.contains { $0.port == 53 })
        // The rest of the lifeline is untouched: the host still reaches the server it has to be released from.
        XCTAssertTrue(rules.contains { $0.address == "203.0.113.7" && $0.port == 8443 })
    }

    func testResolverRulesDropWhatIsNotAnAddressAndCollapseRepeats() {
        let rules = NetworkContainment.resolverRules(for: ["198.51.100.1", "not-an-address", "198.51.100.1", "0.0.0.0", ""])
        XCTAssertEqual(rules.map(\.address), ["198.51.100.1", "198.51.100.1"])
    }

    // Two spellings of one address are one resolver. Collapsing them by string would let a host whose configuration writes an
    // address both ways spend two of the eight slots on it, and crowd out a resolver it actually needs.
    func testResolverRulesCollapseTwoSpellingsOfOneAddress() {
        let rules = NetworkContainment.resolverRules(for: ["fd00::1", "fd00:0:0:0:0:0:0:1", "198.51.100.1"])
        XCTAssertEqual(rules.map(\.address), ["fd00::1", "fd00::1", "198.51.100.1", "198.51.100.1"])
    }

    func testResolverRulesStopAtTheCap() {
        let many = (1...(NetworkContainment.maxResolvers + 4)).map { "198.51.100.\($0)" }
        let rules = NetworkContainment.resolverRules(for: many)
        XCTAssertEqual(Set(rules.map(\.address)).count, NetworkContainment.maxResolvers)
        XCTAssertEqual(rules.count, NetworkContainment.maxResolvers * 2)
    }

    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/releasing-a-host-restores-the-telemetry-settings
    func testAHostThatIsNotContainedHasNoLifelineRules() {
        let release = NetworkContainmentUpdate(version: 6, epoch: 100, contained: false, serverPort: 8443, serverAddresses: ["203.0.113.7"])
        XCTAssertEqual(NetworkContainment.lifeline(for: release, resolvers: ["198.51.100.1"]), [])
    }

    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/a-release-keeps-the-server-flows-allowed
    func testAReleaseKeepsTheReleasedContainmentsServerFlows() {
        let release = NetworkContainmentUpdate(version: 6, epoch: 100, contained: false, serverPort: 0, serverAddresses: [])
        var released = ReleasedLifeline()

        released.accepted(release)
        XCTAssertEqual(released.rules, [], "a host that was never contained keeps nothing")

        released.accepted(contained(port: 8443, addresses: ["203.0.113.7", "2001:db8::7"]))
        XCTAssertEqual(released.rules, [], "a containment carries the server flows in its own lifeline")
        released.accepted(release)
        XCTAssertEqual(released.rules, [
            LifelineRule(address: "203.0.113.7", prefix: 32, port: 8443, transport: .tcp, direction: .outbound),
            LifelineRule(address: "2001:db8::7", prefix: 128, port: 8443, transport: .tcp, direction: .outbound)
        ], "only the server flows: DHCP and DNS go back to the provider")

        released.accepted(NetworkContainmentUpdate(version: 7, epoch: 100, contained: false, serverPort: 0, serverAddresses: []))
        XCTAssertEqual(released.rules.count, 2, "a repeated release keeps the connections the first one kept")
    }

    // A lifeline refresh is accepted before it is applied; if its apply failed the agent is still connected to the endpoint it replaced.
    // Older endpoints are not kept, so the rules stay bounded over a long containment.
    func testAReleaseKeepsTheLatestEndpointAndTheOneItReplaced() {
        var released = ReleasedLifeline()
        let release = NetworkContainmentUpdate(version: 6, epoch: 100, contained: false, serverPort: 0, serverAddresses: [])
        released.accepted(contained(port: 8443, addresses: ["203.0.113.6"]))
        released.accepted(contained(port: 8443, addresses: ["203.0.113.7"]))
        released.accepted(contained(port: 8443, addresses: ["203.0.113.8"]))
        released.accepted(contained(port: 8443, addresses: ["203.0.113.8"]))
        released.accepted(release)
        XCTAssertEqual(released.rules.map(\.address), ["203.0.113.7", "203.0.113.8"],
                       "the replaced endpoint and the latest, nothing older; an unchanged refresh replaces nothing")

        released.accepted(contained(port: 8443, addresses: ["203.0.113.7"]))
        released.accepted(contained(port: 8443, addresses: ["203.0.113.7", "203.0.113.8"]))
        released.accepted(release)
        XCTAssertEqual(released.rules.map(\.address), ["203.0.113.7", "203.0.113.8"], "an address in both endpoints is kept once")

        released.accepted(contained(port: 9443, addresses: ["198.51.100.9"]))
        released.accepted(NetworkContainmentUpdate(version: 8, epoch: 100, contained: false, serverPort: 0, serverAddresses: []))
        XCTAssertEqual(released.rules.map(\.address), ["198.51.100.9"], "a later containment starts over")
    }

    // A starting filter's first settings carry no kept rules, so a release after the start keeps nothing from before it.
    func testAStartingFilterForgetsTheKeptRules() {
        let release = NetworkContainmentUpdate(version: 6, epoch: 100, contained: false, serverPort: 0, serverAddresses: [])
        var released = ReleasedLifeline()
        released.accepted(contained(port: 8443, addresses: ["203.0.113.7"]))
        released.accepted(release)
        released.filterStarting(with: release)
        XCTAssertEqual(released.rules, [])
        released.accepted(NetworkContainmentUpdate(version: 7, epoch: 100, contained: false, serverPort: 0, serverAddresses: []))
        XCTAssertEqual(released.rules, [], "a release after the start keeps nothing from before it")

        released.accepted(contained(port: 8443, addresses: ["203.0.113.8"]))
        released.filterStarting(with: contained(port: 8443, addresses: ["203.0.113.9"]))
        released.accepted(release)
        XCTAssertEqual(released.rules.map(\.address), ["203.0.113.9"],
                       "a filter started contained keeps the connections its first settings allowed, and only those")
    }

    // MARK: store

    private func temporaryPath() -> String {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir.appendingPathComponent("network-containment.json").path
    }

    // spec:extension-network-response/containment-state-is-persisted-and-ordered/containment-survives-an-extension-restart
    func testAnAcceptedContainmentIsLoadedByTheNextStore() {
        let path = temporaryPath()
        let store = NetworkContainmentStore(storagePath: path)
        XCTAssertNil(store.current, "no state is an uncontained host")
        let doc = payload(#"{"version":3,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]}}"#)
        XCTAssertEqual(store.accept(doc), contained())
        XCTAssertEqual(NetworkContainmentStore(storagePath: path).current, contained(), "a restarted extension loads it")
    }

    func testTheStoreRefusesAnOlderUpdateAndAcceptsARefresh() {
        let path = temporaryPath()
        let store = NetworkContainmentStore(storagePath: path)
        let first = payload(#"{"version":3,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]}}"#)
        XCTAssertNotNil(store.accept(first))
        XCTAssertNil(store.accept(payload(#"{"version":2,"epoch":100,"contained":false}"#)), "a delayed release")
        XCTAssertEqual(store.current, contained())
        let refresh = payload(#"{"version":3,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.9"]}}"#)
        XCTAssertEqual(store.accept(refresh), contained(addresses: ["203.0.113.9"]))
        XCTAssertEqual(NetworkContainmentStore(storagePath: path).current, contained(addresses: ["203.0.113.9"]),
                       "the refresh is persisted")
        XCTAssertNil(store.accept(refresh), "redelivering the same refresh changes nothing")
    }

    func testTheStoreRefusesWhatItCannotPersist() {
        let blocker = temporaryPath()
        XCTAssertNoThrow(try AtomicFile.write(Data("x".utf8), toPath: blocker))
        // The storage path lies under a regular file, so the directory cannot be created.
        let store = NetworkContainmentStore(storagePath: blocker + "/network-containment.json")
        XCTAssertNil(store.accept(payload(#"{"version":3,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]}}"#)))
        XCTAssertNil(store.current, "nothing applied that a restart would not load")
    }

    func testAnUnreadablePersistedStateStartsUncontained() {
        let path = temporaryPath()
        XCTAssertNoThrow(try AtomicFile.write(Data("{".utf8), toPath: path))
        XCTAssertNil(NetworkContainmentStore(storagePath: path).current)
    }

    // MARK: status

    // spec:extension-network-response/the-extension-reports-containment-status/the-status-says-whether-containment-was-applied
    // spec:extension-network-response/the-extension-reports-containment-status/the-status-names-the-lifeline-the-filter-enforces
    func testStatusWireShape() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let failed = NetworkContainmentStatus(contained: true, version: 3, epoch: 100, applied: false,
                                              error: "filter not running", appliedAddresses: nil, namesFiltered: nil)
        XCTAssertEqual(String(bytes: try encoder.encode(failed), encoding: .utf8),
                       #"{"applied":false,"contained":true,"epoch":100,"error":"filter not running","version":3}"#)
        let applied = NetworkContainmentStatus(contained: false, version: 4, epoch: 100, applied: true, error: nil,
                                               appliedAddresses: nil, namesFiltered: nil)
        XCTAssertEqual(String(bytes: try encoder.encode(applied), encoding: .utf8),
                       #"{"applied":true,"contained":false,"epoch":100,"version":4}"#, "no error key when it applied")
        // The lifeline the filter holds, which a refresh changes without changing the version or the epoch (issue #1066). Absent
        // rather than null when nothing is applied, so a status from before this field reads the same as one reporting none.
        let refreshed = NetworkContainmentStatus(contained: true, version: 4, epoch: 100, applied: true, error: nil,
                                                 appliedAddresses: ["203.0.113.7", "203.0.113.8"],
                                                 namesFiltered: nil)
        XCTAssertEqual(String(bytes: try encoder.encode(refreshed), encoding: .utf8),
                       #"{"applied":true,"appliedAddresses":["203.0.113.7","203.0.113.8"],"contained":true,"epoch":100,"version":4}"#)
        // Whether the DNS proxy was running, and so whether the restriction on WHICH names resolve was in force (issue #1078). Absent
        // rather than null when unreported, so a status from an extension that predates the field reads as "not reported" rather than
        // as "names are not filtered", which is the reading that would tell an operator a host is leakier than it is.
        let filtered = NetworkContainmentStatus(contained: true, version: 5, epoch: 100, applied: true, error: nil,
                                                appliedAddresses: nil, namesFiltered: true)
        XCTAssertEqual(String(bytes: try encoder.encode(filtered), encoding: .utf8),
                       #"{"applied":true,"contained":true,"epoch":100,"namesFiltered":true,"version":5}"#)
        let unfiltered = NetworkContainmentStatus(contained: true, version: 5, epoch: 100, applied: true, error: nil,
                                                  appliedAddresses: nil, namesFiltered: false)
        XCTAssertEqual(String(bytes: try encoder.encode(unfiltered), encoding: .utf8),
                       #"{"applied":true,"contained":true,"epoch":100,"namesFiltered":false,"version":5}"#,
                       "false is carried, since it is the state an operator has to be told about")
        XCTAssertEqual(NetworkContainmentStatus.eventType, "ne_containment_status")
    }

    // spec:extension-network-response/the-extension-reports-containment-status/the-status-says-whether-names-are-filtered
    //
    // The status reports what the DNS proxy's state makes true, not what the containment asked for: a contained host whose proxy is not
    // running has its DNS restricted by destination alone, and nothing else tells an operator that, since a deliberately disabled
    // provider is dropped from health rather than graded unhealthy.
    func testStatusReportsWhetherNamesAreFiltered() {
        let held = contained(version: 4)
        var tracker = ContainmentStatusTracker()
        tracker.confirmed(held)
        XCTAssertEqual(tracker.status(held: held, namesFiltered: true).namesFiltered, true)
        XCTAssertEqual(tracker.status(held: held, namesFiltered: false).namesFiltered, false,
                       "a contained host whose DNS proxy is not running says so")
        XCTAssertNil(tracker.status(held: held, namesFiltered: nil).namesFiltered)
    }

    // spec:extension-network-response/the-extension-reports-containment-status/a-state-waiting-to-be-applied-is-reported-as-pending
    func testStatusDescribesTheHeldState() {
        let held = contained(version: 4)
        var tracker = ContainmentStatusTracker()
        XCTAssertEqual(tracker.status(held: held, namesFiltered: nil),
                       NetworkContainmentStatus(contained: true, version: 4, epoch: 100, applied: false, error: nil,
                                                appliedAddresses: nil, namesFiltered: nil),
                       "pending before any apply")

        tracker.confirmed(contained(version: 3))
        XCTAssertEqual(tracker.status(held: held, namesFiltered: nil).applied, false,
                       "an older applied state is not reported; the held state is pending")
        XCTAssertNil(tracker.status(held: held, namesFiltered: nil).error)

        tracker.confirmed(held)
        XCTAssertEqual(tracker.status(held: held, namesFiltered: nil),
                       NetworkContainmentStatus(contained: true, version: 4, epoch: 100, applied: true, error: nil,
                                                appliedAddresses: held.serverAddresses, namesFiltered: nil),
                       "a confirmed state names the lifeline the filter holds")

        tracker.failed("content filter is not running")
        tracker.pending()
        XCTAssertEqual(tracker.status(held: held, namesFiltered: nil),
                       NetworkContainmentStatus(contained: true, version: 4, epoch: 100, applied: false, error: nil,
                                                appliedAddresses: nil, namesFiltered: nil),
                       "a filter that started and has yet to apply the held state is pending, not failed")
        tracker.confirmed(held)
        tracker.pending()
        XCTAssertEqual(tracker.status(held: held, namesFiltered: nil).applied, false,
                       "a filter yet to apply the held state is not confirmed by the last")
    }

    // spec:extension-network-response/the-extension-reports-containment-status/a-failed-apply-is-not-reported-as-applied
    func testAFailureClearsAnEarlierConfirmationOfTheSameState() {
        let held = contained(version: 4)
        var tracker = ContainmentStatusTracker()
        tracker.confirmed(held)
        tracker.failed("content filter is not running")
        XCTAssertEqual(tracker.status(held: held, namesFiltered: nil),
                       NetworkContainmentStatus(contained: true, version: 4, epoch: 100, applied: false,
                                                error: "content filter is not running", appliedAddresses: nil, namesFiltered: nil),
                       "a replacement filter that failed to apply the same state is not confirmed by its predecessor")
        tracker.pending()
        XCTAssertNil(tracker.status(held: contained(version: 5), namesFiltered: nil).error, "a new update starts without the earlier state's error")
        tracker.confirmed(contained(version: 5))
        XCTAssertEqual(tracker.status(held: contained(version: 5), namesFiltered: nil).applied, true)
    }

    // MARK: ordering shared with the other pushed documents

    func testPushOrderIsEpochThenVersion() {
        XCTAssertLessThan(PushOrder(epoch: 1, version: 9), PushOrder(epoch: 2, version: 1))
        XCTAssertLessThan(PushOrder(epoch: 2, version: 1), PushOrder(epoch: 2, version: 2))
        XCTAssertEqual(PushOrder(epoch: 2, version: 2), PushOrder(epoch: 2, version: 2))
        XCTAssertFalse(PushOrder(epoch: 2, version: 2) < PushOrder(epoch: 2, version: 2))
    }
}

/// Tests for the ordering bookkeeping behind applying containment filter settings: the event orders a restarting or busy filter can
/// produce, which the controller itself cannot be driven through outside a live network extension.
final class ContainmentSequencerTests: XCTestCase {
    private final class Filter {}

    private func applied(_ decision: ContainmentSequencer<Filter>.ApplyDecision) -> Filter? {
        if case .apply(let filter) = decision { return filter }
        return nil
    }

    func testAStartThatEnforcesTheCurrentStateIsReported() {
        let sequencer = ContainmentSequencer<Filter>()
        let filter = Filter()
        XCTAssertEqual(sequencer.started(filter, startupEnforcesCurrent: true), .report)
        XCTAssertEqual(ContainmentSequencer<Filter>().started(filter, startupEnforcesCurrent: false), .apply)
    }

    func testNoFilterMeansNothingIsApplied() {
        let sequencer = ContainmentSequencer<Filter>()
        guard case .noFilter = sequencer.requestApply() else { return XCTFail("expected no filter") }
    }

    // spec:extension-network-response/the-extension-reports-containment-status/updates-in-quick-succession-apply-in-order
    func testARequestWhileAnApplyIsInFlightIsAppliedAfterItAndOnlyTheLastIsReported() {
        let sequencer = ContainmentSequencer<Filter>()
        let filter = Filter()
        _ = sequencer.started(filter, startupEnforcesCurrent: true)
        let first = applied(sequencer.requestApply())
        XCTAssertTrue(first === filter)
        guard case .deferred = sequencer.requestApply() else { return XCTFail("a second apply must wait for the first") }
        let outcome = sequencer.completed(filter)
        XCTAssertFalse(outcome.report, "the first result is superseded by the request that waited")
        XCTAssertTrue(outcome.applyAgain)
        XCTAssertTrue(applied(sequencer.requestApply()) === filter)
        let last = sequencer.completed(filter)
        XCTAssertTrue(last.report)
        XCTAssertFalse(last.applyAgain)
    }

    // spec:extension-network-response/the-extension-reports-containment-status/a-stopped-filter-s-result-is-not-reported
    func testAStoppedFiltersResultIsNotReportedAndItsReplacementGetsTheState() {
        let sequencer = ContainmentSequencer<Filter>()
        let old = Filter()
        _ = sequencer.started(old, startupEnforcesCurrent: true)
        XCTAssertTrue(applied(sequencer.requestApply()) === old)
        sequencer.stopped(old)
        let replacement = Filter()
        XCTAssertEqual(sequencer.started(replacement, startupEnforcesCurrent: true), .wait, "an apply to the old filter is in flight")
        let outcome = sequencer.completed(old)
        XCTAssertFalse(outcome.report, "the old filter's result does not describe the host")
        XCTAssertTrue(outcome.applyAgain, "the replacement is given the current state")
        XCTAssertTrue(applied(sequencer.requestApply()) === replacement)
    }

    func testStoppedSaysWhetherTheRunningFilterStopped() {
        let sequencer = ContainmentSequencer<Filter>()
        let old = Filter()
        let replacement = Filter()
        _ = sequencer.started(old, startupEnforcesCurrent: true)
        _ = sequencer.started(replacement, startupEnforcesCurrent: true)
        XCTAssertFalse(sequencer.stopped(old), "a late stop from a replaced filter is not the running filter stopping")
        XCTAssertTrue(sequencer.stopped(replacement))
        guard case .noFilter = sequencer.requestApply() else { return XCTFail("no filter is running") }
    }

    func testAStartCompletionAfterItsFiltersStopIsIgnored() {
        let sequencer = ContainmentSequencer<Filter>()
        let old = Filter()
        let replacement = Filter()
        _ = sequencer.started(replacement, startupEnforcesCurrent: true)
        sequencer.stopped(old)
        XCTAssertEqual(sequencer.started(old, startupEnforcesCurrent: true), .ignore)
        XCTAssertTrue(applied(sequencer.requestApply()) === replacement, "the running filter is still the replacement")
    }

    func testAResultAfterTheFilterStoppedWithNoReplacementAppliesNothing() {
        let sequencer = ContainmentSequencer<Filter>()
        let filter = Filter()
        _ = sequencer.started(filter, startupEnforcesCurrent: true)
        _ = sequencer.requestApply()
        sequencer.stopped(filter)
        XCTAssertEqual(sequencer.completed(filter).report, false)
        guard case .noFilter = sequencer.requestApply() else { return XCTFail("no filter is running") }
    }
}
