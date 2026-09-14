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

    // MARK: lifeline

    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/a-contained-host-keeps-only-the-lifeline
    func testLifelineIsTheServerDHCPAndDNS() {
        let rules = NetworkContainment.lifeline(for: contained(port: 8443, addresses: ["203.0.113.7", "2001:db8::7"]))
        XCTAssertEqual(rules, [
            LifelineRule(address: "203.0.113.7", prefix: 32, port: 8443, transport: .tcp, direction: .outbound),
            LifelineRule(address: "2001:db8::7", prefix: 128, port: 8443, transport: .tcp, direction: .outbound),
            LifelineRule(address: "0.0.0.0", prefix: 0, port: 67, transport: .udp, direction: .any),
            LifelineRule(address: "0.0.0.0", prefix: 0, port: 53, transport: .udp, direction: .any),
            LifelineRule(address: "0.0.0.0", prefix: 0, port: 53, transport: .tcp, direction: .any),
            LifelineRule(address: "::", prefix: 0, port: 547, transport: .udp, direction: .any),
            LifelineRule(address: "::", prefix: 0, port: 53, transport: .udp, direction: .any),
            LifelineRule(address: "::", prefix: 0, port: 53, transport: .tcp, direction: .any)
        ])
    }

    // spec:extension-network-response/containment-is-enforced-by-the-operating-system/releasing-a-host-restores-the-telemetry-settings
    func testAHostThatIsNotContainedHasNoLifelineRules() {
        let release = NetworkContainmentUpdate(version: 6, epoch: 100, contained: false, serverPort: 8443, serverAddresses: ["203.0.113.7"])
        XCTAssertEqual(NetworkContainment.lifeline(for: release), [])
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
    func testStatusWireShape() throws {
        let failed = NetworkContainmentStatus(contained: true, version: 3, epoch: 100, applied: false, error: "filter not running")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(failed)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["contained", "version", "epoch", "applied", "error"])
        XCTAssertEqual(object["applied"] as? Bool, false)
        XCTAssertEqual(object["error"] as? String, "filter not running")
        XCTAssertEqual(NetworkContainmentStatus.eventType, "ne_containment_status")
    }
}
