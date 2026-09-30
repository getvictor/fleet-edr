// The credential-store client's watched set and its one filter (issue #1187): which files in which homes are watched, and which
// opens are the browser reading its own store.

@testable import EDRExtensionLogic
import XCTest

final class CredentialStoresTests: XCTestCase {
    /// A home with Chrome (two profiles and the system profile Chrome also keeps), Firefox (one profile and its crash reports),
    /// and nothing else installed.
    private func listing(_ path: String) -> CredentialStores.DirectoryListing {
        switch path {
        case "/Users/alice/Library/Application Support/Google/Chrome/":
            return .entries(["Default", "Profile 1", "System Profile", "Crashpad", "Local State", "Profile x"])
        case "/Users/alice/Library/Application Support/Firefox/Profiles/":
            return .entries(["k7xq2a1b.default-release", "Crash Reports", ".DS_Store"])
        default:
            return .missing
        }
    }

    // spec:endpoint-event-collection/browser-credential-reads-are-reported/every-profile-s-credential-files-are-watched
    func testTargetsAreEveryProfilesCredentialFiles() {
        let targets = CredentialStores.targets(homes: ["/Users/alice"], listDirectory: listing).paths
        let chrome = "/Users/alice/Library/Application Support/Google/Chrome/"
        let firefox = "/Users/alice/Library/Application Support/Firefox/Profiles/k7xq2a1b.default-release/"
        let expected = [
            chrome + "Local State",
            chrome + "Default/Login Data", chrome + "Default/Login Data For Account", chrome + "Default/Web Data",
            chrome + "Default/Cookies", chrome + "Default/Network/Cookies",
            chrome + "Profile 1/Login Data", chrome + "Profile 1/Login Data For Account", chrome + "Profile 1/Web Data",
            chrome + "Profile 1/Cookies", chrome + "Profile 1/Network/Cookies",
            firefox + "logins.json", firefox + "key4.db", firefox + "cookies.sqlite"
        ]
        XCTAssertEqual(targets, expected.sorted(), "System Profile, Crashpad and a non-numbered Profile are not profiles")
    }

    func testTargetsCoverRootsHomeInBothSpellings() {
        let root = "/var/root/Library/Application Support/Firefox/Profiles/"
        let targets = CredentialStores.targets(homes: ["/var/root"]) { $0 == root ? .entries(["a1.default"]) : .missing }.paths
        XCTAssertEqual(targets, [
            "/private/var/root/Library/Application Support/Firefox/Profiles/a1.default/cookies.sqlite",
            "/private/var/root/Library/Application Support/Firefox/Profiles/a1.default/key4.db",
            "/private/var/root/Library/Application Support/Firefox/Profiles/a1.default/logins.json",
            "/var/root/Library/Application Support/Firefox/Profiles/a1.default/cookies.sqlite",
            "/var/root/Library/Application Support/Firefox/Profiles/a1.default/key4.db",
            "/var/root/Library/Application Support/Firefox/Profiles/a1.default/logins.json"
        ])
    }

    func testTargetsAreEmptyWithNoBrowserInstalled() {
        let nothing = CredentialStores.Targets(paths: [], unreadableRoots: [])
        XCTAssertEqual(CredentialStores.targets(homes: ["/Users/bob"]) { _ in .missing }, nothing)
    }

    // A browser directory that fails to list says nothing about what is in it, so the files already watched under it stay watched,
    // while one that no longer exists has its files dropped.
    func testAnUnreadableDirectoryKeepsItsWatchesAndAMissingOneDropsThem() {
        let chrome = "/Users/alice/Library/Application Support/Google/Chrome/"
        let firefox = "/Users/alice/Library/Application Support/Firefox/Profiles/a1.default/"
        let applied = [chrome + "Default/Login Data", firefox + "logins.json"]
        let scanned = CredentialStores.targets(homes: ["/Users/alice"]) { path in
            path == chrome ? .unreadable : .missing
        }
        XCTAssertEqual(scanned.unreadableRoots, [chrome])
        XCTAssertEqual(CredentialStores.next(applied: applied, scanned: scanned), [chrome + "Default/Login Data"],
                       "Chrome could not be listed, so its watch stays; Firefox is gone, so its watch goes")
    }

    func testListingTellsAMissingDirectoryFromAnUnreadableOne() {
        XCTAssertEqual(CredentialStores.listing("/nonexistent/edr-credential-stores"), .missing)
        let file = NSTemporaryDirectory() + "edr-credential-stores-not-a-directory"
        FileManager.default.createFile(atPath: file, contents: Data())
        defer { try? FileManager.default.removeItem(atPath: file) }
        XCTAssertEqual(CredentialStores.listing(file), .unreadable, "a path that exists but cannot be listed")
        XCTAssertEqual(CredentialStores.listing(NSTemporaryDirectory()).isEntries, true)
    }

    // spec:endpoint-event-collection/browser-credential-reads-are-reported/the-browser-s-own-reads-are-not-reported
    func testTheBrowsersOwnReadIsNotReported() {
        let login = "/Users/alice/Library/Application Support/Google/Chrome/Default/Login Data"
        XCTAssertTrue(CredentialStores.isOwnRead(path: login, openerTeamID: "EQHXZ8M8AV"), "Chrome and its helpers")
        XCTAssertFalse(CredentialStores.isOwnRead(path: login, openerTeamID: ""), "an unsigned or Apple tool such as cp or sqlite3")
        XCTAssertFalse(CredentialStores.isOwnRead(path: login, openerTeamID: "43AQ936H96"), "another browser's team")
        let logins = "/Users/alice/Library/Application Support/Firefox/Profiles/a1.default/logins.json"
        XCTAssertTrue(CredentialStores.isOwnRead(path: logins, openerTeamID: "43AQ936H96"), "Firefox")
        XCTAssertFalse(CredentialStores.isOwnRead(path: logins, openerTeamID: "EQHXZ8M8AV"), "Chrome reading Firefox's store")
        XCTAssertFalse(CredentialStores.isOwnRead(path: "/Users/alice/notes.txt", openerTeamID: "EQHXZ8M8AV"), "no owner")
    }

    // spec:endpoint-event-collection/browser-credential-reads-are-reported/profiles-past-the-bound-are-not-watched
    func testChromiumProfilesPastTheBoundAreNotWatched() {
        let chrome = "/Users/alice/Library/Application Support/Google/Chrome/"
        let bound = CredentialStores.maxProfilesPerBrowser
        // Decoys numbered after the real profiles, listed first and in no order, plus zero-padded names that parse to real numbers.
        let numbered = (1...bound * 20).reversed().map { "Profile \($0 + 3)" }
        let padded = (1...bound).map { "Profile " + String(repeating: "0", count: $0) + "1" }
        let decoys = numbered + padded
        let entries = decoys + ["Profile 2", "Default", "Profile 1", "Profile 3"]
        let targets = CredentialStores.targets(homes: ["/Users/alice"]) { $0 == chrome ? .entries(entries) : .missing }
        let profiles = Set(targets.paths.compactMap { path -> String? in
            guard path.hasPrefix(chrome), path.hasSuffix("/Login Data") else {
                return nil
            }
            return String(path.dropFirst(chrome.count).dropLast("/Login Data".count))
        })
        XCTAssertEqual(profiles.count, bound, "at most the bound's profiles are watched")
        for real in ["Default", "Profile 1", "Profile 2", "Profile 3"] {
            XCTAssertTrue(profiles.contains(real), "\(real) is kept ahead of the decoys")
        }
        XCTAssertFalse(profiles.contains { $0.hasPrefix("Profile 0") }, "a zero-padded name is not a profile")
        XCTAssertEqual(targets.paths.count, 1 + bound * CredentialStores.chromiumProfileFiles.count)
        XCTAssertEqual(targets.truncatedRoots, [chrome])
    }

    func testFirefoxProfilesPastTheBoundAreNotWatched() {
        let firefox = "/Users/alice/Library/Application Support/Firefox/Profiles/"
        let bound = CredentialStores.maxProfilesPerBrowser
        let entries = (0..<bound + 1).map { String(format: "p%03d.default", $0) }.reversed()
        let targets = CredentialStores.targets(homes: ["/Users/alice"]) { $0 == firefox ? .entries(Array(entries)) : .missing }
        XCTAssertEqual(targets.paths.count, bound * CredentialStores.firefoxProfileFiles.count)
        XCTAssertFalse(targets.paths.contains { $0.contains(String(format: "p%03d.default", bound)) }, "the last by name is dropped")
        XCTAssertEqual(targets.truncatedRoots, [firefox])
    }

    func testAHomeWithinTheBoundIsNotTruncated() {
        XCTAssertEqual(CredentialStores.targets(homes: ["/Users/alice"], listDirectory: listing).truncatedRoots, [])
    }

    func testIsChromiumProfile() {
        for name in ["Default", "Profile 0", "Profile 1", "Profile 12"] {
            XCTAssertTrue(CredentialStores.isChromiumProfile(name), name)
        }
        let others = [
            "System Profile", "Guest Profile", "Profile", "Profile x", "Profile -1", "Profile 01", "Profile +1", "Crashpad", "Local State"
        ]
        for name in others {
            XCTAssertFalse(CredentialStores.isChromiumProfile(name), name)
        }
    }

    func testOpenFlagsReportTheAccessMode() {
        XCTAssertEqual(CredentialStores.openFlags(fflag: 0x1), Int(O_RDONLY))
        XCTAssertEqual(CredentialStores.openFlags(fflag: 0x2), Int(O_WRONLY))
        XCTAssertEqual(CredentialStores.openFlags(fflag: 0x3), Int(O_RDWR))
        XCTAssertEqual(CredentialStores.openFlags(fflag: 0x1 | 0x400), Int(O_RDONLY), "other flags do not change the mode")
    }
}

private extension CredentialStores.DirectoryListing {
    var isEntries: Bool {
        if case .entries = self {
            return true
        }
        return false
    }
}
