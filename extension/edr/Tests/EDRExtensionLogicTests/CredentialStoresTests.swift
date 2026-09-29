// The credential-store client's watched set and its one filter (issue #1187): which files in which homes are watched, and which
// opens are the browser reading its own store.

@testable import EDRExtensionLogic
import XCTest

final class CredentialStoresTests: XCTestCase {
    /// A home with Chrome (two profiles and the system profile Chrome also keeps), Firefox (one profile and its crash reports),
    /// and nothing else installed.
    private func listing(_ path: String) -> [String]? {
        switch path {
        case "/Users/alice/Library/Application Support/Google/Chrome/":
            return ["Default", "Profile 1", "System Profile", "Crashpad", "Local State", "Profile x"]
        case "/Users/alice/Library/Application Support/Firefox/Profiles/":
            return ["k7xq2a1b.default-release", "Crash Reports", ".DS_Store"]
        default:
            return nil
        }
    }

    // spec:endpoint-event-collection/browser-credential-reads-are-reported/every-profile-s-credential-files-are-watched
    func testTargetsAreEveryProfilesCredentialFiles() {
        let targets = CredentialStores.targets(homes: ["/Users/alice"], listDirectory: listing)
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
        let targets = CredentialStores.targets(homes: ["/var/root"]) { $0 == root ? ["a1.default"] : nil }
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
        XCTAssertEqual(CredentialStores.targets(homes: ["/Users/bob"]) { _ in nil }, [])
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

    func testIsChromiumProfile() {
        for name in ["Default", "Profile 0", "Profile 1", "Profile 12"] {
            XCTAssertTrue(CredentialStores.isChromiumProfile(name), name)
        }
        for name in ["System Profile", "Guest Profile", "Profile", "Profile x", "Profile -1", "Crashpad", "Local State"] {
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
