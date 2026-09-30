import Foundation

/// CredentialBrowser is a browser whose saved passwords and cookies the credential-store client watches (issue #1187): where its
/// profiles live below a home, how they are laid out, and the Developer ID team that signs the browser and its helpers.
struct CredentialBrowser: Sendable {
    /// Layout is where a browser keeps its credential files.
    enum Layout: Sendable {
        /// chromium keeps one subdirectory per profile (`Default`, `Profile 1`, ...), and one `Local State` beside them.
        case chromium
        /// firefox keeps one randomly named subdirectory per profile under `Profiles/`.
        case firefox
    }

    /// root is the browser's profile directory relative to a home, ending in "/".
    let root: String
    /// teamID is the team that signs the browser. An open by a process signed by it is the browser reading its own store.
    let teamID: String
    let layout: Layout
}

/// CredentialStores is the credential-store client's watched set and its one decision, which opens are the browser's own.
///
/// Infostealers read these files to take saved passwords and session cookies, and nothing else reports a read: the file-tamper
/// client sees only writes. Each file is watched as a literal path rather than its browser's directory as a prefix, because a
/// browser opens thousands of files under its own directory and a prefix would wake the client for every one of them.
///
/// Pure Foundation, with no EndpointSecurity import, so it is unit-testable; CredentialStoreSubscriber applies it.
enum CredentialStores {
    /// browsers are the ones watched. Safari is not among them: its cookies are TCC-protected and read constantly by Apple's own
    /// WebKit processes, which need a filter of their own.
    static let browsers: [CredentialBrowser] = [
        CredentialBrowser(root: "Library/Application Support/Google/Chrome/", teamID: "EQHXZ8M8AV", layout: .chromium),
        CredentialBrowser(root: "Library/Application Support/BraveSoftware/Brave-Browser/", teamID: "KL8N8XSYF4", layout: .chromium),
        CredentialBrowser(root: "Library/Application Support/Microsoft Edge/", teamID: "UBF8T346G9", layout: .chromium),
        CredentialBrowser(root: "Library/Application Support/Arc/User Data/", teamID: "S6N382Y83G", layout: .chromium),
        CredentialBrowser(root: "Library/Application Support/Vivaldi/", teamID: "4XF3XNRN6Y", layout: .chromium),
        CredentialBrowser(root: "Library/Application Support/Firefox/Profiles/", teamID: "43AQ936H96", layout: .firefox)
    ]

    /// chromiumProfileFiles are a Chromium profile's saved passwords, form data and cookies. Cookies moved under `Network/` in
    /// Chrome 96, and both places are watched because other Chromium browsers moved at their own pace.
    static let chromiumProfileFiles = ["Login Data", "Login Data For Account", "Web Data", "Cookies", "Network/Cookies"]
    /// chromiumRootFiles sit beside the profiles. `Local State` holds the key material the profiles' secrets are wrapped with.
    static let chromiumRootFiles = ["Local State"]
    /// firefoxProfileFiles are a Firefox profile's saved logins, the key database that decrypts them, and its cookies.
    static let firefoxProfileFiles = ["logins.json", "key4.db", "cookies.sqlite"]
    /// maxProfilesPerBrowser bounds the profiles watched in one browser directory. Any user can create profile directories in their
    /// own home, so without a bound a script making thousands of them would have the client mute that many literal paths on every
    /// refresh. Browsers number and name profiles far below this, and the profiles kept are the ones a browser creates first.
    static let maxProfilesPerBrowser = 50

    /// DirectoryListing is what listing a browser's profile directory found. A missing directory is a browser that is not installed
    /// and contributes nothing; an unreadable one says nothing about what is there, so the files already watched under it are kept.
    enum DirectoryListing: Equatable {
        case entries([String])
        case missing
        case unreadable
    }

    /// Targets is the result of a scan: the credential files to watch, the browser directories that could not be read, and the
    /// ones holding more profiles than maxProfilesPerBrowser, whose profiles past the bound are not watched.
    struct Targets: Equatable {
        let paths: [String]
        let unreadableRoots: [String]
        var truncatedRoots: [String] = []
    }

    /// targets is every credential file path to watch in the given homes: each browser's files in each of its profiles, in both
    /// spellings of a firmlinked root, sorted and without duplicates, along with the browser directories whose listing failed.
    static func targets(homes: [String], listDirectory: (String) -> DirectoryListing) -> Targets {
        var out = Set<String>()
        var unreadable: [String] = []
        var truncated: [String] = []
        for home in homes {
            for browser in browsers {
                let root = home + "/" + browser.root
                switch listDirectory(root) {
                case .missing:
                    continue
                case .unreadable:
                    unreadable.append(contentsOf: WatchedPaths.spellings(of: root))
                case .entries(let entries):
                    let found = profiles(in: entries, layout: browser.layout)
                    if found.count > maxProfilesPerBrowser {
                        truncated.append(root)
                    }
                    let kept = Array(found.prefix(maxProfilesPerBrowser))
                    for path in files(in: root, profiles: kept, layout: browser.layout) {
                        out.formUnion(WatchedPaths.spellings(of: path))
                    }
                }
            }
        }
        return Targets(paths: out.sorted(), unreadableRoots: unreadable.sorted(), truncatedRoots: truncated.sorted())
    }

    /// next is the set a refresh applies: the scanned paths, and every path already applied under a directory the scan could not
    /// read, so a directory that fails to list for a moment does not stop its files being watched.
    static func next(applied: [String], scanned: Targets) -> [String] {
        let kept = applied.filter { path in scanned.unreadableRoots.contains { path.hasPrefix($0) } }
        return Array(Set(scanned.paths).union(kept)).sorted()
    }

    /// listing lists a directory with the file manager, telling a directory that does not exist from one that could not be read.
    static func listing(_ path: String) -> DirectoryListing {
        do {
            return .entries(try FileManager.default.contentsOfDirectory(atPath: path))
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError {
            return .missing
        } catch {
            return .unreadable
        }
    }

    /// profiles is a browser directory's profiles in the order the bound keeps them. Chromium's come as `Default` and then by number,
    /// the order the browser creates them in, so profiles made to crowd out the real ones can only take numbers after them. Firefox
    /// names its profiles randomly, so its are sorted by name, which is at least the same set on every refresh.
    static func profiles(in entries: [String], layout: CredentialBrowser.Layout) -> [String] {
        switch layout {
        case .chromium:
            return entries.compactMap { name in chromiumProfileNumber(name).map { (name, $0) } }
                .sorted { $0.1 < $1.1 }
                .map(\.0)
        case .firefox:
            // A Firefox profile directory is named `<random>.<name>`, as in `k7xq2a1b.default-release`.
            return entries.filter { $0.contains(".") && !$0.hasPrefix(".") }.sorted()
        }
    }

    private static func files(in root: String, profiles: [String], layout: CredentialBrowser.Layout) -> [String] {
        switch layout {
        case .chromium:
            return chromiumRootFiles.map { root + $0 }
                + profiles.flatMap { profile in chromiumProfileFiles.map { root + profile + "/" + $0 } }
        case .firefox:
            return profiles.flatMap { profile in firefoxProfileFiles.map { root + profile + "/" + $0 } }
        }
    }

    /// isChromiumProfile reports whether a directory entry is a Chromium profile: `Default`, or `Profile ` and a number.
    static func isChromiumProfile(_ name: String) -> Bool {
        chromiumProfileNumber(name) != nil
    }

    /// chromiumProfileNumber is where a Chromium profile sorts: first for `Default`, and N for `Profile N` written as Chromium writes
    /// it, so `Profile 01` cannot stand in for `Profile 1`. Nil for any other entry.
    private static func chromiumProfileNumber(_ name: String) -> Int? {
        if name == "Default" {
            return Int.min
        }
        let prefix = "Profile "
        guard name.hasPrefix(prefix) else {
            return nil
        }
        let digits = String(name.dropFirst(prefix.count))
        guard let number = Int(digits), number >= 0, String(number) == digits else {
            return nil
        }
        return number
    }

    /// owner is the browser whose store a path is in, or nil for any other path.
    static func owner(of path: String) -> CredentialBrowser? {
        browsers.first { path.contains("/" + $0.root) }
    }

    /// isOwnRead reports whether an open of path is the browser reading its own store: the opener is signed by the browser's team.
    /// Everything else is reported, Apple's own tools included, since `cp`, `sqlite3` and `ditto` are what infostealers read the
    /// files with; the server decides what to raise and what an operator has excluded.
    static func isOwnRead(path: String, openerTeamID: String) -> Bool {
        guard let owner = owner(of: path) else {
            return false
        }
        return !openerTeamID.isEmpty && openerTeamID == owner.teamID
    }

    /// openFlags maps an open's kernel file flags to the open(2) access mode the `open` event carries: O_RDONLY, O_WRONLY or
    /// O_RDWR. A read-only open is what a theft usually is, but `sqlite3` opens a database read-write by default, so every access
    /// mode is reported.
    static func openFlags(fflag: Int32) -> Int {
        switch (fflag & fread != 0, fflag & fwrite != 0) {
        case (true, true):
            return Int(O_RDWR)
        case (false, true):
            return Int(O_WRONLY)
        default:
            return Int(O_RDONLY)
        }
    }

    /// fread and fwrite are the kernel's FREAD and FWRITE file flags (sys/fcntl.h), which Swift does not import.
    private static let fread: Int32 = 0x1
    private static let fwrite: Int32 = 0x2
}
