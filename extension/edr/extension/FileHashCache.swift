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
}
