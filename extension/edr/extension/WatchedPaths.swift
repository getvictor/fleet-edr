import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "WatchedPaths")

/// WatchedPathMatch is how a watched path covers files, and maps one-to-one onto the Endpoint Security target mute types the
/// file-tamper client applies it with.
enum WatchedPathMatch: String, Sendable {
    /// literal covers exactly the file at the path.
    case literal
    /// prefix covers every path that starts with it, at any depth. A prefix meant as a directory ends in "/", or it would also
    /// cover a sibling that merely shares the leading characters (`/etc/sudoers.d` would match `/etc/sudoers.d.bak`).
    case prefix
}

/// WatchedPath is one entry in the set of file paths the file-tamper client observes.
struct WatchedPath: Hashable, Sendable {
    let path: String
    let match: WatchedPathMatch
}

/// WatchedPathsUpdate is a decoded `watched_paths.update`: the server's version for the set, the entries this extension applies, and
/// how many entries it skipped because it did not understand them.
struct WatchedPathsUpdate: Equatable {
    let version: Int64
    let paths: [WatchedPath]
    let skipped: Int
}

/// WatchedPaths is the file-tamper client's watched set (ADR-0008 step 4, issue #998): which paths it observes, and how a set pushed
/// by the server combines with the paths this extension always watches.
///
/// Pure Foundation, with no EndpointSecurity import, so the set arithmetic is unit-testable; FileTamperSubscriber applies the result.
enum WatchedPaths {
    /// builtIn is watched whatever the server pushes. The shipped sudoers rules depend on these paths, so no configuration can take
    /// them away; a pushed set only adds to them.
    static let builtIn: [WatchedPath] = [
        WatchedPath(path: "/etc/sudoers", match: .literal),
        WatchedPath(path: "/etc/sudoers.d/", match: .prefix)
    ]

    /// firmlinkedRoots are the top-level directories macOS keeps under /private and links from the root. Endpoint Security reports
    /// the resolved /private form, and a path is muted in both spellings so an entry works however it was written.
    private static let firmlinkedRoots = ["/etc", "/tmp", "/var"]

    private struct Document: Decodable {
        let version: Int64
        let paths: [Entry]
    }

    private struct Entry: Decodable {
        let path: String
        let match: String
    }

    /// decode reads a `watched_paths.update` payload. It returns nil for a payload that is not a watched-path document at all, which
    /// leaves the active set untouched. Within a valid document, an entry whose match type this extension does not know, or whose path
    /// is not absolute, is skipped and counted rather than failing the whole set: an older extension should keep watching what it
    /// understands when a newer server adds a kind of entry.
    static func decode(_ data: Data) -> WatchedPathsUpdate? {
        guard let document = try? JSONDecoder().decode(Document.self, from: data) else {
            return nil
        }
        var paths: [WatchedPath] = []
        for entry in document.paths {
            guard entry.path.hasPrefix("/"), let match = WatchedPathMatch(rawValue: entry.match) else {
                continue
            }
            paths.append(WatchedPath(path: entry.path, match: match))
        }
        return WatchedPathsUpdate(version: document.version, paths: paths, skipped: document.paths.count - paths.count)
    }

    /// targets is every path the client mutes for a pushed set: the built-in paths, then the pushed ones, each in both spellings of a
    /// firmlinked root, without duplicates and in a stable order.
    static func targets(pushed: [WatchedPath]) -> [WatchedPath] {
        var seen = Set<WatchedPath>()
        var out: [WatchedPath] = []
        for entry in builtIn + pushed {
            for path in spellings(of: entry.path) {
                let target = WatchedPath(path: path, match: entry.match)
                if seen.insert(target).inserted {
                    out.append(target)
                }
            }
        }
        return out
    }

    /// spellings returns a path in its /private form first, then its root-linked form, when it lies under a firmlinked root, and the
    /// path alone otherwise.
    static func spellings(of path: String) -> [String] {
        for root in firmlinkedRoots {
            if path == root || path.hasPrefix(root + "/") {
                return ["/private" + path, path]
            }
            let privateRoot = "/private" + root
            if path == privateRoot || path.hasPrefix(privateRoot + "/") {
                return [path, String(path.dropFirst("/private".count))]
            }
        }
        return [path]
    }

    /// changes is what moving from the applied targets to the next ones takes: the targets to mute and the targets to unmute, each in
    /// the order of `next` and `applied` respectively. Muting the additions before unmuting the removals means a path in both sets is
    /// never touched, so nothing already watched stops being watched while a set changes.
    static func changes(from applied: [WatchedPath], to next: [WatchedPath]) -> (mute: [WatchedPath], unmute: [WatchedPath]) {
        let appliedSet = Set(applied)
        let nextSet = Set(next)
        return (next.filter { !appliedSet.contains($0) }, applied.filter { !nextSet.contains($0) })
    }
}

/// WatchedPathStore keeps the last pushed set on disk, so a restarted extension watches it from its first event rather than falling
/// back to the built-in paths until the agent next pushes.
struct WatchedPathStore {
    /// defaultStoragePath sits beside the application-control snapshot, in the directory the extension already owns.
    static let defaultStoragePath = "/var/db/com.fleetdm.edr/watched-paths.json"

    let storagePath: String

    init(storagePath: String = WatchedPathStore.defaultStoragePath) {
        self.storagePath = storagePath
    }

    /// load returns the persisted set, or nil when there is none or it cannot be read, in which case the client watches the built-in
    /// paths alone until the agent pushes a set.
    func load() -> WatchedPathsUpdate? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: storagePath)) else {
            return nil
        }
        guard let update = WatchedPaths.decode(data) else {
            logger.warning("persisted watched-path set could not be decoded; watching the built-in paths")
            return nil
        }
        return update
    }

    /// save persists a payload exactly as it was pushed, written atomically so a crash mid-write cannot leave a torn file.
    func save(_ data: Data) {
        let url = URL(fileURLWithPath: storagePath)
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: url, options: .atomic)
        } catch {
            logger.error("watched-path set persist failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
