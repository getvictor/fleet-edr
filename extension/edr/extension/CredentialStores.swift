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
    /// maxProfilesPerBrowser bounds the profiles one browser directory gets literal watches for. Any user can create profile
    /// directories in their own home, so without a bound a script making thousands of them would have the client mute that many
    /// literal paths on every refresh. Past it the directory is watched as a prefix instead, and the open handler keeps only the
    /// credential files, so no profile goes unwatched and profiles made to crowd out the real ones have nothing to crowd out.
    static let maxProfilesPerBrowser = 50

    /// DirectoryListing is what listing a browser's profile directory found. A missing directory is a browser that is not installed
    /// and contributes nothing; an unreadable one says nothing about what is there, so the files already watched under it are kept.
    enum DirectoryListing: Equatable {
        case entries([String])
        case missing
        case unreadable
    }

    /// Targets is the result of a scan: the credential files to watch as literal paths, the browser directories holding more than
    /// maxProfilesPerBrowser profiles, watched as prefixes instead, and the browser directories that could not be read.
    struct Targets: Equatable {
        let paths: [String]
        var prefixes: [String] = []
        let unreadableRoots: [String]
    }

    /// targets is every credential file path to watch in the given homes: each browser's files in each of its profiles, in both
    /// spellings of a firmlinked root, sorted and without duplicates, along with the browser directories whose listing failed.
    static func targets(homes: [String], listDirectory: (String) -> DirectoryListing) -> Targets {
        var out = Set<String>()
        var prefixes = Set<String>()
        var unreadable: [String] = []
        for home in homes {
            for browser in browsers {
                let root = home + "/" + browser.root
                switch listDirectory(root) {
                case .missing:
                    continue
                case .unreadable:
                    unreadable.append(contentsOf: WatchedPaths.spellings(of: root))
                case .entries(let entries):
                    let profiles = entries.filter { isProfile($0, layout: browser.layout) }
                    guard profiles.count <= maxProfilesPerBrowser else {
                        prefixes.formUnion(WatchedPaths.spellings(of: root))
                        continue
                    }
                    for path in files(in: root, profiles: profiles, layout: browser.layout) {
                        out.formUnion(WatchedPaths.spellings(of: path))
                    }
                }
            }
        }
        return Targets(paths: out.sorted(), prefixes: prefixes.sorted(), unreadableRoots: unreadable.sorted())
    }

    /// next is the set a refresh applies, for literal paths or for prefixes alike: the scanned ones, and every one already applied
    /// under a directory the scan could not read, so a directory that fails to list for a moment does not stop being watched.
    static func next(applied: [String], scanned: [String], unreadableRoots: [String]) -> [String] {
        let kept = applied.filter { path in unreadableRoots.contains { path.hasPrefix($0) } }
        return Array(Set(scanned).union(kept)).sorted()
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

    private static func files(in root: String, profiles: [String], layout: CredentialBrowser.Layout) -> [String] {
        switch layout {
        case .chromium:
            return chromiumRootFiles.map { root + $0 }
                + profiles.flatMap { profile in chromiumProfileFiles.map { root + profile + "/" + $0 } }
        case .firefox:
            return profiles.flatMap { profile in firefoxProfileFiles.map { root + profile + "/" + $0 } }
        }
    }

    private static func isProfile(_ name: String, layout: CredentialBrowser.Layout) -> Bool {
        switch layout {
        case .chromium:
            return isChromiumProfile(name)
        case .firefox:
            // A Firefox profile directory is named `<random>.<name>`, as in `k7xq2a1b.default-release`.
            return name.contains(".") && !name.hasPrefix(".")
        }
    }

    /// isChromiumProfile reports whether a directory entry is a Chromium profile: `Default`, or `Profile ` and a number written as
    /// Chromium writes it, so `Profile 01` is not a second spelling of `Profile 1`.
    static func isChromiumProfile(_ name: String) -> Bool {
        if name == "Default" {
            return true
        }
        let prefix = "Profile "
        guard name.hasPrefix(prefix) else {
            return false
        }
        let digits = String(name.dropFirst(prefix.count))
        guard let number = Int(digits) else {
            return false
        }
        return number >= 0 && String(number) == digits
    }

    /// isCredentialFile reports whether a path is one of the files a browser keeps its credentials in, which is every file the
    /// client watches and none of the others a prefix watch on a browser directory also delivers.
    static func isCredentialFile(_ path: String) -> Bool {
        guard let owner = owner(of: path), let range = path.range(of: "/" + owner.root) else {
            return false
        }
        let rest = path[range.upperBound...]
        if owner.layout == .chromium, chromiumRootFiles.contains(String(rest)) {
            return true
        }
        guard let slash = rest.firstIndex(of: "/") else {
            return false
        }
        let profile = String(rest[..<slash])
        let file = String(rest[rest.index(after: slash)...])
        switch owner.layout {
        case .chromium:
            return isChromiumProfile(profile) && chromiumProfileFiles.contains(file)
        case .firefox:
            return isProfile(profile, layout: .firefox) && firefoxProfileFiles.contains(file)
        }
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
