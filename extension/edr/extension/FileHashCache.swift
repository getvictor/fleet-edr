import CryptoKit
import Darwin
import Foundation
import os

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "FileHashCache")

/// FileHashCache memoises SHA-256 digests of executable Mach-O files keyed
/// by their on-disk identity tuple `(inode, mtimeSec, mtimeNsec)`. The
/// AUTH_EXEC decision engine consults the cache on every exec; cache misses
/// trigger a non-blocking async fill so the AUTH callback never waits on
/// disk I/O. Cache hits on the regular NOTIFY_EXEC path also save a redundant
/// hash compute when the binary has already been hashed once.
///
/// Cache key choice. macOS `es_file_t.stat` is available on every AUTH_EXEC
/// without an extra `stat()` syscall, and inode+mtime is the canonical
/// "same file" fingerprint on a POSIX filesystem: a different inode means
/// a different file (e.g. atomic-replace updates), and a different mtime
/// means the same inode has been modified in place. We deliberately do NOT
/// key on path: the same Mach-O file can be reached via multiple paths
/// (hard links, symlinks resolved upstream), and keying on path would miss
/// the cache for legitimate "same file" execs.
///
/// Streaming hash. SHA-256 runs over 64 KiB chunks read through a
/// FileHandle so a multi-gigabyte binary doesn't have to fit in memory.
/// CryptoKit.SHA256's update/finalize API supports incremental hashing.
final class FileHashCache {
    /// 64 KiB chunks balance memory pressure against syscall count for streaming
    /// SHA-256 over Mach-O binaries: large enough that hashing a typical
    /// multi-MB executable does only ~tens of reads, small enough that a
    /// concurrent run on a gigabyte-class binary doesn't bloat resident set.
    private static let hashReadChunkBytes = 65_536

    static let shared = FileHashCache()

    private struct Key: Hashable {
        let device: Int32
        let inode: UInt64
        let mtimeSec: Int64
        let mtimeNsec: Int64
    }

    private let lock = OSAllocatedUnfairLock(initialState: [Key: String]())
    // Concurrent dispatch queue is fine here because every write to the
    // cache goes through the OSAllocatedUnfairLock and every reader either
    // sees the full hex string or "not yet cached". The queue's only job
    // is to keep the fill work off the AUTH_EXEC callback thread.
    private let computeQueue = DispatchQueue(
        label: "com.fleetdm.edr.filehashcache.compute",
        qos: .userInitiated,
        attributes: .concurrent
    )

    /// lookup returns the cached SHA-256 hex string for the file identified
    /// by stat, or nil if no entry exists yet. Pure cache read; never
    /// blocks. The AUTH_EXEC handler is the only intended caller on the
    /// hot path.
    func lookup(stat fileStat: stat) -> String? {
        let key = Self.makeKey(from: fileStat)
        return lock.withLock { $0[key] }
    }

    /// lookupOrCompute returns the cached hash if present, otherwise reads
    /// the file synchronously and stores the result. Intended for the
    /// NOTIFY_EXEC path, which has no kernel deadline and where every
    /// event has a chance to carry a real hash for downstream telemetry.
    /// Returns nil if the file cannot be read (deleted between AUTH and
    /// NOTIFY, permissions, etc.); the caller emits the event without the
    /// hash rather than dropping it entirely.
    func lookupOrCompute(path: String, stat fileStat: stat) -> String? {
        let key = Self.makeKey(from: fileStat)
        if let cached = lock.withLock({ $0[key] }) {
            return cached
        }
        guard let hash = Self.computeSHA256(path: path, expected: fileStat) else {
            return nil
        }
        lock.withLock { $0[key] = hash }
        return hash
    }

    /// lookupOrComputeWithDeadline is the AUTH_EXEC variant of lookupOrCompute. Reads the cache first (the common warm-case
    /// path that costs no disk I/O). On a miss, attempts a synchronous chunked SHA-256 with a budget bounded by the kernel
    /// deadline carried on es_message_t.deadline. A cache write happens only on a clean .computed outcome; .deadlineExceeded
    /// and .readFailed leave the cache empty so the next exec retries.
    ///
    /// Why sync hashing replaces the previous lazy-fill ALLOW: the previous handler returned ALLOW on every cold cache and
    /// kicked an async fill, meaning the first exec of any binary always slipped past BINARY rules. An attacker who only needs
    /// one execution to win (drop, persist, reboot) defeated Application Control completely; an attacker mutating
    /// (dev,inode,mtime) on every exec made the bypass deterministic. Sync compute on the AUTH callback thread is the only
    /// honest way to enforce identity-based rules on the kernel's first-look event, with the deadline carrying the operator's
    /// chosen latency budget. See #208.
    func lookupOrComputeWithDeadline(path: String, stat fileStat: stat, deadlineMachAbs: UInt64) -> HashOutcome {
        let key = Self.makeKey(from: fileStat)
        if let cached = lock.withLock({ $0[key] }) {
            return .computed(cached)
        }
        let outcome = Self.computeSHA256WithDeadline(path: path, expected: fileStat, deadlineMachAbs: deadlineMachAbs)
        if case let .computed(hash) = outcome {
            lock.withLock { $0[key] = hash }
        }
        return outcome
    }

    /// startLazyFill triggers an asynchronous hash compute IF the cache
    /// does not already have an entry. Used by the AUTH_EXEC handler on
    /// cache miss so the next exec of the same binary hits the cache. Safe
    /// to call repeatedly; concurrent fills for the same key compute the
    /// same value and the last write wins.
    func startLazyFill(path: String, stat fileStat: stat) {
        let key = Self.makeKey(from: fileStat)
        let alreadyCached = lock.withLock { $0[key] != nil }
        if alreadyCached {
            return
        }
        let capturedPath = path
        let capturedStat = fileStat
        computeQueue.async {
            // Recheck under the lock after the queue resumes so we don't
            // race against a synchronous lookupOrCompute that may have
            // populated the cache between the alreadyCached check and the
            // async dispatch.
            let stillEmpty = self.lock.withLock { $0[key] == nil }
            if !stillEmpty {
                return
            }
            guard let hash = Self.computeSHA256(path: capturedPath, expected: capturedStat) else {
                return
            }
            self.lock.withLock { $0[key] = hash }
        }
    }

    private static func makeKey(from fileStat: stat) -> Key {
        Key(
            device: fileStat.st_dev,
            inode: UInt64(fileStat.st_ino),
            mtimeSec: Int64(fileStat.st_mtimespec.tv_sec),
            mtimeNsec: Int64(fileStat.st_mtimespec.tv_nsec)
        )
    }

    /// computeSHA256 hashes the file at path, but only after re-stating
    /// the open file handle and confirming its (dev, inode, mtime) tuple
    /// still matches the expected stat from the originating ES event.
    /// Without this TOCTOU guard a replace-between-AUTH-and-read can
    /// associate a different file's hash with the original cache key,
    /// poisoning future decisions. Mismatch → nil; the caller's cache
    /// entry stays empty and the next exec re-stats.
    private static func computeSHA256(path: String, expected: stat) -> String? {
        let url = URL(fileURLWithPath: path)
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            logger.warning("could not open file for hashing: \(path, privacy: .public)")
            return nil
        }
        defer { try? handle.close() }
        // Verify the opened handle still points at the file the ES event
        // told us about. If the file was atomically replaced between AUTH
        // and our read, the underlying inode (or device, or mtime) will
        // differ; abort and let the caller fall back to "no hash yet".
        var openedStat = stat()
        let fd = handle.fileDescriptor
        guard fstat(fd, &openedStat) == 0 else {
            logger.warning("fstat failed on \(path, privacy: .public)")
            return nil
        }
        if !Self.statMatches(expected: expected, actual: openedStat) {
            logger.warning("file replaced between AUTH and hash read: \(path, privacy: .public)")
            return nil
        }
        var hasher = SHA256()
        while true {
            do {
                guard let chunk = try handle.read(upToCount: Self.hashReadChunkBytes), !chunk.isEmpty else {
                    break
                }
                hasher.update(data: chunk)
            } catch {
                logger.warning("hash read failed: \(error.localizedDescription, privacy: .public)")
                return nil
            }
        }
        let digest = hasher.finalize()
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func statMatches(expected: stat, actual: stat) -> Bool {
        expected.st_dev == actual.st_dev
            && expected.st_ino == actual.st_ino
            && expected.st_mtimespec.tv_sec == actual.st_mtimespec.tv_sec
            && expected.st_mtimespec.tv_nsec == actual.st_mtimespec.tv_nsec
    }

    /// safetyMarginNs is the headroom we reserve below the kernel-supplied AUTH_EXEC deadline. Hashing aborts and the caller
    /// applies the snapshot's deadlineFallback posture once the remaining budget drops below this value. 500ms covers the
    /// post-hash work (snapshot map lookup, kernel respond, optional event/notification dispatch) plus a margin for an
    /// unlucky page-in stall before the kernel kills the ES client for missing its deadline.
    private static let safetyMarginNs: UInt64 = 500_000_000

    /// computeSHA256WithDeadline streams the file at path through SHA-256 in 64-KiB chunks, checking the remaining mach
    /// absolute-time budget between chunks and aborting if the remaining budget would not cover safetyMarginNs of post-hash
    /// work. Same TOCTOU re-stat guard as computeSHA256 -- a replace-between-AUTH-and-read returns .readFailed so the caller
    /// does NOT poison the cache with a hash of the wrong file. The hashReadChunkBytes (64 KiB) chunk size is fine-grained
    /// enough that even a multi-gigabyte binary yields multiple deadline checks per second of compute time; smaller chunks
    /// would only increase syscall overhead without measurably tightening the abort window.
    static func computeSHA256WithDeadline(path: String, expected: stat, deadlineMachAbs: UInt64) -> HashOutcome {
        let url = URL(fileURLWithPath: path)
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            logger.warning("could not open file for hashing: \(path, privacy: .public)")
            return .readFailed
        }
        defer { try? handle.close() }
        var openedStat = stat()
        let fd = handle.fileDescriptor
        guard fstat(fd, &openedStat) == 0 else {
            logger.warning("fstat failed on \(path, privacy: .public)")
            return .readFailed
        }
        if !Self.statMatches(expected: expected, actual: openedStat) {
            logger.warning("file replaced between AUTH and hash read: \(path, privacy: .public)")
            return .readFailed
        }
        var hasher = SHA256()
        while true {
            if Self.machAbsNsRemaining(until: deadlineMachAbs) < Self.safetyMarginNs {
                return .deadlineExceeded
            }
            do {
                guard let chunk = try handle.read(upToCount: Self.hashReadChunkBytes), !chunk.isEmpty else {
                    break
                }
                hasher.update(data: chunk)
            } catch {
                logger.warning("hash read failed: \(error.localizedDescription, privacy: .public)")
                return .readFailed
            }
        }
        let digest = hasher.finalize()
        return .computed(digest.map { String(format: "%02x", $0) }.joined())
    }

    /// machTimebase is the per-process conversion ratio between mach absolute time units and nanoseconds. Initialised once
    /// (mach_timebase_info is documented as constant for the lifetime of the process). nonisolated(unsafe) because the value
    /// is set exactly once at first use and read-only thereafter; Swift 6's strict concurrency cannot prove this from the
    /// type system, but the access pattern is correct.
    private nonisolated(unsafe) static var machTimebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// machAbsNsRemaining returns ns of budget remaining until deadlineMachAbs. Returns 0 once the deadline has passed; the
    /// caller treats "remaining < safetyMarginNs" as "do not start another chunk." The conversion uses UInt64 widening to
    /// avoid an overflow on hours-long deadlines (Mac mach absolute time runs in single-digit-ns units, so a 1-hour offset
    /// fits in UInt64 with headroom; doing the multiply in narrower types would not).
    private static func machAbsNsRemaining(until deadlineMachAbs: UInt64) -> UInt64 {
        let now = mach_absolute_time()
        if now >= deadlineMachAbs {
            return 0
        }
        let diff = deadlineMachAbs - now
        let info = Self.machTimebase
        return diff &* UInt64(info.numer) / UInt64(info.denom)
    }
}
