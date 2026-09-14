import Foundation
import os

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

/// WatchedPathsUpdate is a decoded `watched_paths.update`: the server's version and epoch for the set, the entries this extension
/// applies, and how many entries it skipped.
struct WatchedPathsUpdate: Equatable {
    let version: Int64
    /// epoch is the set's server update time in Unix microseconds, 0 when the server sent none. It orders sets across a server
    /// database restore that regresses version, the same role policy_epoch plays for application control (#322).
    let epoch: Int64
    let paths: [WatchedPath]
    let skipped: Int

    /// supersedes reports whether this update should replace `current`, the last one accepted. Sets are ordered by epoch, then by
    /// version: the server forces each update time past the one in its database, so epoch orders every set that database issues,
    /// and after a restore sends version backwards the next set is ahead once the database clock is past any epoch the restore
    /// lost. Version breaks a tie, which is what orders sets from a server that sends no epoch. An update that is not ahead is a
    /// delayed or duplicate delivery, and applying it would put an older set back over a newer one. Commands can reach the agent
    /// out of order (a poll returns pending commands newest first, and the poll and the control stream can overlap), so this is
    /// the gate that keeps the newest set in force. Application control orders its snapshots the same way
    /// (ApplicationControlStore.apply).
    func supersedes(_ current: WatchedPathsUpdate?) -> Bool {
        guard let current else { return true }
        return PushOrder(epoch: epoch, version: version) > PushOrder(epoch: current.epoch, version: current.version)
    }
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
        let epoch: Int64?
        let paths: [Entry]
    }

    private struct Entry: Decodable {
        let path: String
        let match: String
    }

    /// decode reads a `watched_paths.update` payload. It returns nil for a payload that is not a watched-path document at all, which
    /// leaves the active set untouched. Within a valid document, an entry the extension would not watch (see isAcceptable) is skipped
    /// and counted rather than failing the whole set, so an older extension keeps watching what it understands when a newer server adds
    /// a kind of entry.
    static func decode(_ data: Data) -> WatchedPathsUpdate? {
        guard let document = try? JSONDecoder().decode(Document.self, from: data) else {
            return nil
        }
        var paths: [WatchedPath] = []
        for entry in document.paths {
            guard let match = WatchedPathMatch(rawValue: entry.match), isAcceptable(entry.path, match) else {
                continue
            }
            paths.append(WatchedPath(path: entry.path, match: match))
        }
        return WatchedPathsUpdate(
            version: document.version, epoch: document.epoch ?? 0, paths: paths, skipped: document.paths.count - paths.count
        )
    }

    /// isAcceptable is the server's rule for one entry (ValidateWatchedPaths in server/rules/api), held again here.
    ///
    /// The server is where a set is validated, but a mute is applied here, and what reaches the kernel is a C string: a path carrying a
    /// NUL, or `..` segments, can read as a deep path to a component count while muting a top-level one, and a top-level prefix puts
    /// every write under that tree on the wire, the firehose ADR-0008 removed after it delayed detection by about 12 minutes. A server
    /// bug should not be able to bring that back, so every rule the server applies to an entry is applied again: an absolute path whose
    /// /private spelling fits within maxPathBytes, free of ASCII control characters (NUL included), with no empty, `.` or `..` segment;
    /// a literal that does not end in "/"; and a prefix that ends in "/" and lies below a top-level directory, judged through /private
    /// for /etc, /tmp and /var.
    static func isAcceptable(_ path: String, _ match: WatchedPathMatch) -> Bool {
        // Every spelling the client mutes must fit, and the /private one of a firmlinked path is the longer.
        guard path.hasPrefix("/"), spellings(of: path).allSatisfy({ $0.utf8.count <= maxPathBytes }),
              !path.unicodeScalars.contains(where: { $0.value < firstPrintable || $0.value == deleteCharacter }) else {
            return false
        }
        let body = path.dropFirst()
        let trimmed = body.hasSuffix("/") ? body.dropLast() : body
        let segments = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        guard !segments.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else {
            return false
        }
        switch match {
        case .literal:
            return !path.hasSuffix("/")
        case .prefix:
            let rootLinked = spellings(of: path).last ?? path
            return path.hasSuffix("/") && rootLinked.split(separator: "/").count >= minimumPrefixDepth
        }
    }

    /// maxPathBytes is the longest path es_mute_path can take: PATH_MAX (1024) counts the terminating NUL of the C string. The server's
    /// MaxWatchedPathBytes.
    private static let maxPathBytes = 1023
    /// firstPrintable and deleteCharacter bound the control characters a path may not carry.
    private static let firstPrintable: UInt32 = 0x20
    private static let deleteCharacter: UInt32 = 0x7f
    /// minimumPrefixDepth is how many path components a prefix needs: a top-level directory is one, so a prefix must name something
    /// inside one.
    private static let minimumPrefixDepth = 2

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

/// WatchedPathStore keeps the last accepted set: on disk, so a restarted extension watches it from its first event rather than falling
/// back to the built-in paths until the agent next pushes, and in memory, so a delayed older set is recognised and turned away.
final class WatchedPathStore: Sendable {
    /// defaultStoragePath sits beside the application-control snapshot, in the directory the extension already owns.
    static let defaultStoragePath = "/var/db/com.fleetdm.edr/watched-paths.json"

    let storagePath: String
    private let accepted: OSAllocatedUnfairLock<WatchedPathsUpdate?>

    /// init reads the persisted set, which becomes the baseline a pushed set must supersede.
    init(storagePath: String = WatchedPathStore.defaultStoragePath) {
        self.storagePath = storagePath
        self.accepted = OSAllocatedUnfairLock(initialState: nil)
        let persisted = load()
        accepted.withLock { $0 = persisted }
    }

    /// current is the last accepted set, or nil when none has been.
    var current: WatchedPathsUpdate? {
        accepted.withLock { $0 }
    }

    /// accept decodes a pushed payload and, when it supersedes the last accepted set and has been persisted, records it and returns it
    /// for the caller to apply. It returns nil, changing nothing, for a payload that is not a watched-path document, a set that does not
    /// supersede the current one, or a set that could not be written to disk.
    ///
    /// Persisting comes before accepting so the running set and the one a restart loads never disagree: a set applied without being
    /// written would vanish at the next restart, and, already accepted, could not be retried by a redelivery. Refused instead, it is
    /// retried by the next delivery of the same set.
    ///
    /// Called from the XPC server's serial queue, which is what makes the check, the write and the commit a sequence nothing else
    /// interleaves with.
    func accept(_ data: Data) -> WatchedPathsUpdate? {
        guard let update = WatchedPaths.decode(data), update.supersedes(current), save(data) else {
            return nil
        }
        accepted.withLock { $0 = update }
        return update
    }

    /// load returns the persisted set, or nil when there is none or it cannot be read, in which case the client watches the built-in
    /// paths alone until the agent pushes a set.
    private func load() -> WatchedPathsUpdate? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: storagePath)) else {
            return nil
        }
        guard let update = WatchedPaths.decode(data) else {
            logger.warning("persisted watched-path set could not be decoded; watching the built-in paths")
            return nil
        }
        return update
    }

    /// save persists a payload exactly as it was pushed, written atomically so a crash mid-write cannot leave a torn file, and reports
    /// whether it was written.
    private func save(_ data: Data) -> Bool {
        do {
            try AtomicFile.write(data, toPath: storagePath)
            return true
        } catch {
            logger.error("watched-path set not applied, persist failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }
}
