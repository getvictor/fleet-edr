// Watched paths that name a path in every user's home (`~/...`, issue #1167): which entries are accepted, which accounts' homes
// they expand into, and what the client mutes for them. Kept apart from WatchedPathsTests, which is near its length caps.

@testable import EDRExtensionLogic
import XCTest

final class HomeWatchedPathsTests: XCTestCase {
    // spec:endpoint-event-collection/a-watched-path-can-name-every-user-s-home/a-home-entry-is-judged-below-the-home
    //
    // A `~/` entry is judged as the path it would be in a home at the top of the filesystem, so a prefix needs two components below
    // the home, as an absolute prefix needs two below the root: `~/Library/` would put every write in every Library on the wire.
    func testIsAcceptableJudgesAHomeEntryBelowTheHome() {
        let accepted: [(String, WatchedPathMatch)] = [
            ("~/.ssh/authorized_keys", .literal),
            ("~/Library/LaunchAgents/", .prefix),
            ("~/.zshrc", .literal)
        ]
        for (path, match) in accepted {
            XCTAssertTrue(WatchedPaths.isAcceptable(path, match), path)
        }
        let refused: [RefusedHomeEntry] = [
            RefusedHomeEntry(path: "~/", match: .prefix, why: "the whole home"),
            RefusedHomeEntry(path: "~/Library/", match: .prefix, why: "a top-level directory of the home"),
            RefusedHomeEntry(path: "~/.ssh/", match: .literal, why: "literal ending in a slash"),
            RefusedHomeEntry(path: "~/../etc/", match: .prefix, why: "dot-dot out of the home"),
            RefusedHomeEntry(path: "~//.ssh/authorized_keys", match: .literal, why: "empty segment"),
            RefusedHomeEntry(path: "~/.ssh/authorized_keys\u{0}", match: .literal, why: "NUL"),
            RefusedHomeEntry(path: "~", match: .literal, why: "the home itself"),
            RefusedHomeEntry(path: "~alice/.ssh/authorized_keys", match: .literal, why: "another user's home by name")
        ]
        for entry in refused {
            XCTAssertFalse(WatchedPaths.isAcceptable(entry.path, entry.match), entry.why)
        }
    }

    private struct RefusedHomeEntry {
        let path: String
        let match: WatchedPathMatch
        let why: String
    }

    // spec:endpoint-event-collection/a-watched-path-can-name-every-user-s-home/a-home-entry-covers-root-and-every-person-s-home
    func testHomesAreRootsAndEachPersonsOnceEach() {
        let homes = WatchedPaths.homes(of: [
            (uid: 0, directory: "/var/root"),
            (uid: 501, directory: "/Users/alice"),
            (uid: 502, directory: "/Users/bob/"),
            (uid: 503, directory: "/Users/alice"),
            (uid: 70, directory: "/Library/WebServer"),
            (uid: 4_294_967_294, directory: "/var/empty"),
            (uid: 1_000_001, directory: "/Users/network.user"),
            (uid: 504, directory: "relative/home"),
            (uid: 505, directory: "/")
        ])
        XCTAssertEqual(homes, ["/Users/alice", "/Users/bob", "/Users/network.user", "/var/root"])
    }

    func testTargetsExpandAHomeEntryIntoEveryHomeInBothSpellings() {
        let targets = WatchedPaths.targets(
            pushed: [WatchedPath(path: "~/.ssh/authorized_keys", match: .literal)], homes: ["/Users/alice", "/var/root"]
        )
        XCTAssertEqual(Array(targets.dropFirst(WatchedPaths.targets(pushed: []).count)), [
            WatchedPath(path: "/Users/alice/.ssh/authorized_keys", match: .literal),
            WatchedPath(path: "/private/var/root/.ssh/authorized_keys", match: .literal),
            WatchedPath(path: "/var/root/.ssh/authorized_keys", match: .literal)
        ])
    }

    func testTargetsDropAnExpansionThatWouldNotBeWatched() {
        let long = "~/" + String(repeating: "a", count: 1000)
        let targets = WatchedPaths.targets(
            pushed: [WatchedPath(path: long, match: .literal)], homes: ["/Users/alice", "/Users/" + String(repeating: "b", count: 40)]
        )
        let pushedTargets = targets.dropFirst(WatchedPaths.targets(pushed: []).count)
        XCTAssertEqual(pushedTargets.map(\.path), ["/Users/alice/" + String(repeating: "a", count: 1000)],
                       "the home whose expansion passes PATH_MAX is left out, the one that fits is watched")
    }

    func testTargetsWithNoHomesMuteNothingForAHomeEntry() {
        XCTAssertEqual(
            WatchedPaths.targets(pushed: [WatchedPath(path: "~/.ssh/authorized_keys", match: .literal)], homes: []),
            WatchedPaths.targets(pushed: [])
        )
    }

    // An absolute entry is not touched by the homes, so a set with no `~/` entries mutes what it always did.
    func testTargetsLeaveAnAbsoluteEntryAlone() {
        let entry = WatchedPath(path: "/Library/StartupItems/", match: .prefix)
        XCTAssertEqual(WatchedPaths.targets(pushed: [entry], homes: ["/Users/alice"]), WatchedPaths.targets(pushed: [entry]))
    }

    func testDecodeKeepsAHomeEntry() throws {
        let data = Data(#"{"version": 3, "paths": [{"path": "~/.ssh/authorized_keys", "match": "literal"}]}"#.utf8)
        let update = try XCTUnwrap(WatchedPaths.decode(data))
        XCTAssertEqual(update.paths, [WatchedPath(path: "~/.ssh/authorized_keys", match: .literal)])
        XCTAssertEqual(update.skipped, 0)
    }

    // The account list the host really has: this runs the directory-service walk the client runs, so a change that broke it (no
    // accounts returned) fails here rather than silently watching nothing. Every host has root.
    func testHomeDirectoriesReadsTheHostsAccounts() {
        XCTAssertTrue(WatchedPaths.homeDirectories().contains("/var/root"))
    }
}
