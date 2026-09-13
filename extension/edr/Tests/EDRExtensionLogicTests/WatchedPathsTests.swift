import Foundation
@testable import EDRExtensionLogic
import XCTest

/// Tests for the file-tamper client's watched set (issue #998): decoding a pushed set, combining it with the built-in sudoers paths,
/// and the mute/unmute difference between two sets. Applying that difference to a live Endpoint Security client is exercised at the
/// system / VM layer, because FileTamperSubscriber imports EndpointSecurity and is outside this target.
final class WatchedPathsTests: XCTestCase {
    private struct RefusedEntry {
        let path: String
        let match: WatchedPathMatch
        let why: String
    }

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
            epoch: 0,
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
          {"path": "/Users/victor/qa", "match": "recursive_glob"},
          {"path": "relative/path", "match": "literal"}
        ]}
        """))
        XCTAssertEqual(update?.paths, [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])
        XCTAssertEqual(update?.skipped, 2)
    }

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/a-prefix-at-the-top-of-the-filesystem-is-not-watched
    func testDecodeSkipsAPrefixAtTheTopOfTheFilesystem() {
        let update = WatchedPaths.decode(payload("""
        {"version": 3, "paths": [
          {"path": "/", "match": "prefix"},
          {"path": "/Users/", "match": "prefix"},
          {"path": "/private/etc/", "match": "prefix"},
          {"path": "/private/", "match": "prefix"},
          {"path": "/Users", "match": "literal"},
          {"path": "/etc/emond.d/", "match": "prefix"}
        ]}
        """))
        // A literal names one file, so only prefixes are held to the rule; /private/etc/ is judged as /etc/.
        XCTAssertEqual(update?.paths, [
            WatchedPath(path: "/Users", match: .literal),
            WatchedPath(path: "/etc/emond.d/", match: .prefix)
        ])
        XCTAssertEqual(update?.skipped, 4)
    }

    // The same cases the server's ValidateWatchedPaths refuses, so a set that got past the server by a bug is still not watched.
    func testIsAcceptableRefusesEverythingTheServerRefuses() {
        let refused: [RefusedEntry] = [
            RefusedEntry(path: "etc/hosts", match: .literal, why: "relative path"),
            RefusedEntry(path: "", match: .literal, why: "empty path"),
            RefusedEntry(path: "/etc//hosts", match: .literal, why: "empty segment"),
            RefusedEntry(path: "/etc/./hosts", match: .literal, why: "dot segment"),
            RefusedEntry(path: "/Library/../Users/", match: .prefix, why: "dot-dot segment"),
            RefusedEntry(path: "/Users/child/../", match: .prefix, why: "dot-dot segment that reads as deep"),
            RefusedEntry(path: "/etc/ho\nsts", match: .literal, why: "control character"),
            RefusedEntry(path: "/Users/\u{0}ignored/", match: .prefix, why: "NUL, which truncates to a top-level prefix at the kernel"),
            RefusedEntry(path: "/etc/hosts\u{7f}", match: .literal, why: "delete character"),
            RefusedEntry(path: "/" + String(repeating: "a", count: 1023), match: .literal,
                         why: "no room for the C string's NUL in PATH_MAX"),
            RefusedEntry(path: "/etc/" + String(repeating: "a", count: 1023 - "/etc/".count), match: .literal,
                         why: "fits as written but not in the /private spelling the kernel reports"),
            RefusedEntry(path: "/Library/StartupItems/", match: .literal, why: "literal ending in a slash"),
            RefusedEntry(path: "/Library/StartupItems", match: .prefix, why: "prefix without a trailing slash"),
            RefusedEntry(path: "/", match: .prefix, why: "root prefix"),
            RefusedEntry(path: "/Users/", match: .prefix, why: "top-level prefix"),
            RefusedEntry(path: "/private/etc/", match: .prefix, why: "top-level prefix through the firmlink"),
            RefusedEntry(path: "/private/", match: .prefix, why: "firmlink parent itself")
        ]
        for entry in refused {
            XCTAssertFalse(WatchedPaths.isAcceptable(entry.path, entry.match), entry.why)
        }
    }

    func testIsAcceptableAcceptsWhatTheServerAccepts() {
        let accepted: [(String, WatchedPathMatch)] = [
            ("/Library/StartupItems/", .prefix),
            ("/etc/emond.d/rules/", .prefix),
            ("/private/var/root/.ssh/", .prefix),
            ("/Users/Shared/canary.docx", .literal),
            ("/etc/sudoers", .literal),
            ("/Library/" + String(repeating: "a", count: 1023 - "/Library/".count), .literal)
        ]
        for (path, match) in accepted {
            XCTAssertTrue(WatchedPaths.isAcceptable(path, match), path)
        }
    }

    func testDecodeReadsTheEpochWhenPresent() {
        XCTAssertEqual(WatchedPaths.decode(payload(#"{"version": 2, "epoch": 1789300000000000, "paths": []}"#))?.epoch, 1_789_300_000_000_000)
    }

    // MARK: supersedes

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/an-older-set-delivered-late-does-not-replace-a-newer-one
    func testSupersedesOnlyWhenVersionOrEpochIsAhead() {
        func update(_ version: Int64, _ epoch: Int64) -> WatchedPathsUpdate {
            WatchedPathsUpdate(version: version, epoch: epoch, paths: [], skipped: 0)
        }
        XCTAssertTrue(update(1, 10).supersedes(nil), "anything supersedes having no set")
        XCTAssertTrue(update(3, 30).supersedes(update(2, 20)))
        XCTAssertFalse(update(2, 20).supersedes(update(3, 30)), "an older set delivered late")
        XCTAssertFalse(update(3, 30).supersedes(update(3, 30)), "the same set delivered twice")
        // After a server database restore the version goes back, but the next change carries a later epoch.
        XCTAssertTrue(update(1, 40).supersedes(update(3, 30)))
        // A server that sends no epoch is ordered by version alone.
        XCTAssertTrue(update(4, 0).supersedes(update(3, 0)))
        XCTAssertFalse(update(3, 0).supersedes(update(4, 0)))
    }

    func testDecodeRejectsAPayloadThatIsNotAWatchedPathDocument() {
        XCTAssertNil(WatchedPaths.decode(payload("not json")))
        XCTAssertNil(WatchedPaths.decode(payload(#"{"paths": []}"#)), "a document without a version is not a watched-path set")
        XCTAssertNil(WatchedPaths.decode(payload(#"{"version": 1}"#)), "a document without paths is not a watched-path set")
    }

    func testDecodeAcceptsAnEmptySet() {
        XCTAssertEqual(WatchedPaths.decode(payload(#"{"version": 4, "paths": []}"#)), WatchedPathsUpdate(version: 4, epoch: 0, paths: [], skipped: 0))
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

    private func temporaryStore() -> WatchedPathStore {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return WatchedPathStore(storagePath: directory.appendingPathComponent("watched-paths.json").path)
    }

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/a-pushed-set-survives-an-extension-restart
    func testStoreAcceptsAndPersistsAPushedSet() {
        let store = temporaryStore()
        XCTAssertNil(store.current, "nothing pushed yet")

        let accepted = store.accept(payload(#"{"version": 9, "epoch": 90, "paths": [{"path": "/Library/StartupItems/", "match": "prefix"}]}"#))
        XCTAssertEqual(accepted?.paths, [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])

        let restarted = WatchedPathStore(storagePath: store.storagePath)
        XCTAssertEqual(restarted.current?.version, 9)
        XCTAssertEqual(restarted.current?.epoch, 90)
        XCTAssertEqual(restarted.current?.paths, [WatchedPath(path: "/Library/StartupItems/", match: .prefix)])
    }

    func testStoreTurnsAwayAnOlderSetAndKeepsTheNewerOnePersisted() {
        let store = temporaryStore()
        XCTAssertNotNil(store.accept(payload(#"{"version": 2, "epoch": 20, "paths": [{"path": "/etc/emond.d/", "match": "prefix"}]}"#)))

        XCTAssertNil(store.accept(payload(#"{"version": 1, "epoch": 10, "paths": [{"path": "/Library/StartupItems/", "match": "prefix"}]}"#)))
        XCTAssertNil(store.accept(payload(#"{"version": 2, "epoch": 20, "paths": []}"#)), "a redelivery of the set in force")

        XCTAssertEqual(store.current?.version, 2)
        XCTAssertEqual(WatchedPathStore(storagePath: store.storagePath).current?.paths, [WatchedPath(path: "/etc/emond.d/", match: .prefix)])
    }

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/a-malformed-push-leaves-the-watched-set-unchanged
    func testStoreLeavesTheSetAloneForAPayloadThatIsNotAWatchedPathDocument() {
        let store = temporaryStore()
        XCTAssertNotNil(store.accept(payload(#"{"version": 2, "paths": [{"path": "/etc/emond.d/", "match": "prefix"}]}"#)))

        XCTAssertNil(store.accept(payload(#"{"version": 3, "paths": [{"path": 5, "match": "prefix"}]}"#)))

        XCTAssertEqual(store.current?.version, 2)
        XCTAssertEqual(WatchedPathStore(storagePath: store.storagePath).current?.version, 2)
    }

    // spec:endpoint-event-collection/the-watched-path-set-is-pushed-by-the-server/a-set-that-cannot-be-persisted-is-not-applied
    // A set that cannot be written is not applied, so the running set never differs from the one a restart loads, and a redelivery
    // once the disk recovers still counts as new.
    func testStoreDoesNotAcceptASetItCannotPersist() throws {
        let blocker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: blocker) }
        try Data("not a directory".utf8).write(to: blocker)
        let store = WatchedPathStore(storagePath: blocker.appendingPathComponent("watched-paths.json").path)

        XCTAssertNil(store.accept(payload(#"{"version": 1, "epoch": 10, "paths": [{"path": "/etc/emond.d/", "match": "prefix"}]}"#)))
        XCTAssertNil(store.current)
    }

    func testStoreStartsEmptyFromAnUnreadableFile() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        addTeardownBlock { try? FileManager.default.removeItem(at: file) }
        try Data("{".utf8).write(to: file)
        XCTAssertNil(WatchedPathStore(storagePath: file.path).current)
    }
}
