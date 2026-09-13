import Foundation
@testable import EDRExtensionLogic
import XCTest

/// Tests for the file-tamper client's watched set (issue #998): decoding a pushed set, combining it with the built-in sudoers paths,
/// and the mute/unmute difference between two sets. Applying that difference to a live Endpoint Security client is exercised at the
/// system / VM layer, because FileTamperSubscriber imports EndpointSecurity and is outside this target.
final class WatchedPathsTests: XCTestCase {
    private func payload(_ json: String) -> Data {
        Data(json.utf8)
    }

    // MARK: decode

    func testDecodeReadsVersionAndEntries() {
        let update = WatchedPaths.decode(payload("""
        {"version": 7, "paths": [
          {"path": "/Library/StartupItems/", "match": "prefix"},
          {"path": "/etc/emond.d/rules/rule.plist", "match": "literal"}
        ]}
        """))
        XCTAssertEqual(update, WatchedPathsUpdate(
            version: 7,
            paths: [
                WatchedPath(path: "/Library/StartupItems/", match: .prefix),
                WatchedPath(path: "/etc/emond.d/rules/rule.plist", match: .literal)
            ],
            skipped: 0
        ))
    }

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/an-entry-the-extension-does-not-understand-is-skipped
    func testDecodeSkipsEntriesItCannotApplyAndKeepsTheRest() {
        let update = WatchedPaths.decode(payload("""
        {"version": 3, "paths": [
          {"path": "/Library/StartupItems/", "match": "prefix"},
          {"path": "/Users/", "match": "recursive_glob"},
          {"path": "relative/path", "match": "literal"}
        ]}
        """))
        XCTAssertEqual(update?.paths, [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])
        XCTAssertEqual(update?.skipped, 2)
    }

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/a-malformed-push-leaves-the-watched-set-unchanged
    func testDecodeRejectsAPayloadThatIsNotAWatchedPathDocument() {
        XCTAssertNil(WatchedPaths.decode(payload("not json")))
        XCTAssertNil(WatchedPaths.decode(payload(#"{"paths": []}"#)), "a document without a version is not a watched-path set")
        XCTAssertNil(WatchedPaths.decode(payload(#"{"version": 1}"#)), "a document without paths is not a watched-path set")
    }

    func testDecodeAcceptsAnEmptySet() {
        XCTAssertEqual(WatchedPaths.decode(payload(#"{"version": 4, "paths": []}"#)), WatchedPathsUpdate(version: 4, paths: [], skipped: 0))
    }

    // MARK: targets

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/the-built-in-paths-stay-watched-whatever-is-pushed
    func testTargetsWithNothingPushedAreExactlyTheBuiltInSudoersPaths() {
        // The set the client muted before the set became configurable, in the same order.
        XCTAssertEqual(WatchedPaths.targets(pushed: []), [
            WatchedPath(path: "/private/etc/sudoers", match: .literal),
            WatchedPath(path: "/etc/sudoers", match: .literal),
            WatchedPath(path: "/private/etc/sudoers.d/", match: .prefix),
            WatchedPath(path: "/etc/sudoers.d/", match: .prefix)
        ])
    }

    func testTargetsAddPushedPathsAfterTheBuiltInOnesWithoutDuplicates() {
        let targets = WatchedPaths.targets(pushed: [
            WatchedPath(path: "/Library/StartupItems/", match: .prefix),
            WatchedPath(path: "/etc/sudoers", match: .literal),
            WatchedPath(path: "/Library/StartupItems/", match: .prefix)
        ])
        XCTAssertEqual(Array(targets.prefix(4)), WatchedPaths.targets(pushed: []))
        XCTAssertEqual(Array(targets.dropFirst(4)), [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])
    }

    func testTargetsKeepTheMatchTypeOfEachEntry() {
        let targets = WatchedPaths.targets(pushed: [WatchedPath(path: "/etc/sudoers", match: .prefix)])
        XCTAssertTrue(targets.contains(WatchedPath(path: "/etc/sudoers", match: .prefix)))
        XCTAssertTrue(targets.contains(WatchedPath(path: "/etc/sudoers", match: .literal)))
    }

    // MARK: spellings

    func testSpellingsCoverBothFormsOfAFirmlinkedRoot() {
        XCTAssertEqual(WatchedPaths.spellings(of: "/etc/emond.d/"), ["/private/etc/emond.d/", "/etc/emond.d/"])
        XCTAssertEqual(WatchedPaths.spellings(of: "/private/var/root/.ssh/"), ["/private/var/root/.ssh/", "/var/root/.ssh/"])
        XCTAssertEqual(WatchedPaths.spellings(of: "/tmp"), ["/private/tmp", "/tmp"])
    }

    func testSpellingsLeaveOtherPathsAlone() {
        XCTAssertEqual(WatchedPaths.spellings(of: "/Library/StartupItems/"), ["/Library/StartupItems/"])
        XCTAssertEqual(WatchedPaths.spellings(of: "/etcetera/file"), ["/etcetera/file"], "a root only matches at a path boundary")
        XCTAssertEqual(WatchedPaths.spellings(of: "/private/etcetera"), ["/private/etcetera"])
    }

    // MARK: changes

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/a-pushed-set-is-applied-without-a-restart
    func testChangesMuteOnlyTheAdditionsAndUnmuteOnlyTheRemovals() {
        let startup = WatchedPath(path: "/Library/StartupItems/", match: .prefix)
        let emond = WatchedPath(path: "/etc/emond.d/", match: .prefix)
        let applied = WatchedPaths.targets(pushed: [startup])
        let next = WatchedPaths.targets(pushed: [emond])

        let (mute, unmute) = WatchedPaths.changes(from: applied, to: next)

        XCTAssertEqual(mute, [WatchedPath(path: "/private/etc/emond.d/", match: .prefix), emond])
        XCTAssertEqual(unmute, [startup])
    }

    func testChangesBetweenEqualSetsAreEmpty() {
        let targets = WatchedPaths.targets(pushed: [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])
        let (mute, unmute) = WatchedPaths.changes(from: targets, to: targets)
        XCTAssertTrue(mute.isEmpty)
        XCTAssertTrue(unmute.isEmpty)
    }

    func testChangesNeverUnmuteABuiltInPath() {
        let applied = WatchedPaths.targets(pushed: [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])
        let (_, unmute) = WatchedPaths.changes(from: applied, to: WatchedPaths.targets(pushed: []))
        XCTAssertTrue(Set(unmute).isDisjoint(with: WatchedPaths.targets(pushed: [])))
    }

    // MARK: WatchedPathStore

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/a-pushed-set-survives-an-extension-restart
    func testStoreRoundTripsAPushedPayload() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let store = WatchedPathStore(storagePath: directory.appendingPathComponent("watched-paths.json").path)
        XCTAssertNil(store.load(), "nothing pushed yet")

        store.save(payload(#"{"version": 9, "paths": [{"path": "/Library/StartupItems/", "match": "prefix"}]}"#))

        let reloaded = WatchedPathStore(storagePath: store.storagePath).load()
        XCTAssertEqual(reloaded?.version, 9)
        XCTAssertEqual(reloaded?.paths, [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])
    }

    func testStoreIgnoresAnUnreadableFile() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        addTeardownBlock { try? FileManager.default.removeItem(at: file) }
        try Data("{".utf8).write(to: file)
        XCTAssertNil(WatchedPathStore(storagePath: file.path).load())
    }
}
