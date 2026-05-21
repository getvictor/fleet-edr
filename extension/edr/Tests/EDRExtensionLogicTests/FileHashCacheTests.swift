// FileHashCache tests: write a real file under FileManager.default.temporaryDirectory,
// stat it to obtain the live (dev, inode, mtime) tuple FileHashCache keys on, then
// drive lookup / lookupOrCompute / startLazyFill. The cache is a singleton -- tests
// use uniquely-generated file paths so cache entries from one test never collide
// with another's. The shared cache still grows across tests; that's intentional --
// it mirrors how the AUTH_EXEC handler hits the cache in production.

import CryptoKit
import Darwin
import Foundation
@testable import EDRExtensionLogic
import XCTest

final class FileHashCacheTests: XCTestCase {
    /// makeTempFile writes `bytes` into a fresh path under the test temp dir and
    /// returns the path plus the live stat used as the cache key. The caller is
    /// responsible for cleanup at addTeardownBlock time.
    private func makeTempFile(bytes: Data, file: StaticString = #filePath, line: UInt = #line) throws -> (path: String, stat: stat) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("EDRFileHashCacheTests", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("hash-\(UUID().uuidString).bin")
        try bytes.write(to: url)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
        }
        var st = stat()
        let rc = stat(url.path, &st)
        XCTAssertEqual(rc, 0, "stat() must succeed on freshly-written temp file", file: file, line: line)
        return (url.path, st)
    }

    /// expectedSHA256 returns the lowercase hex SHA-256 of `bytes`, mirroring the
    /// production hash format (32-byte digest formatted as 64 lowercase hex chars).
    private func expectedSHA256(of bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - lookup

    func testLookupReturnsNilForUncachedFile() throws {
        let file = try makeTempFile(bytes: Data("lookup-cold".utf8))
        // First-time lookup must be a cache miss: lookup() does NOT trigger a fill,
        // it just reads the dictionary. The AUTH_EXEC fast path relies on this.
        XCTAssertNil(FileHashCache.shared.lookup(stat: file.stat))
    }

    // MARK: - lookupOrCompute

    func testLookupOrComputeReturnsExpectedHashAndCaches() throws {
        let payload = Data("hello cache".utf8)
        let file = try makeTempFile(bytes: payload)
        let expected = expectedSHA256(of: payload)

        let firstHash = FileHashCache.shared.lookupOrCompute(path: file.path, stat: file.stat)
        XCTAssertEqual(firstHash, expected)

        // After the synchronous compute, a plain lookup() with the same stat must
        // hit the cache.
        XCTAssertEqual(FileHashCache.shared.lookup(stat: file.stat), expected)

        // Calling lookupOrCompute a second time returns the same value (cache hit
        // path -- file is still on disk, but the implementation should not need
        // to re-read it).
        let secondHash = FileHashCache.shared.lookupOrCompute(path: file.path, stat: file.stat)
        XCTAssertEqual(secondHash, expected)
    }

    func testLookupOrComputeReturnsNilForMissingFile() {
        // No file at this path -- FileHandle(forReadingFrom:) throws, the function
        // logs a warning and returns nil rather than crashing.
        var fakeStat = stat()
        fakeStat.st_dev = 1
        fakeStat.st_ino = 999_999
        fakeStat.st_mtimespec.tv_sec = 0
        fakeStat.st_mtimespec.tv_nsec = 0
        let path = "/tmp/edr-fileHashCacheTests-does-not-exist-\(UUID().uuidString)"
        XCTAssertNil(FileHashCache.shared.lookupOrCompute(path: path, stat: fakeStat))
    }

    func testLookupOrComputeReturnsNilOnInodeMismatch() throws {
        // TOCTOU guard: caller passes a stat whose (dev, inode, mtime) tuple does
        // NOT match what fstat() reports for the opened FD. The function must
        // refuse to hash and return nil so the cache stays empty rather than
        // associating a wrong hash with the bogus key.
        let file = try makeTempFile(bytes: Data("real-content".utf8))
        var bogus = file.stat
        // Forge a different inode value to simulate "file was replaced between
        // AUTH and read." Real value is whatever fstat would return; we offset.
        bogus.st_ino = file.stat.st_ino &+ 9999
        XCTAssertNil(FileHashCache.shared.lookupOrCompute(path: file.path, stat: bogus))
        // A failed compute must NOT cache anything under the forged key -- if it did, the next
        // AUTH_EXEC presenting that bogus (dev, ino, mtime) tuple would happily get served a wrong
        // hash via a plain `lookup()`. Pin the negative so a future regression that quietly stores
        // nil-or-stale-hash entries fails loudly.
        XCTAssertNil(FileHashCache.shared.lookup(stat: bogus))
        // The honest stat still produces the hash.
        let honest = FileHashCache.shared.lookupOrCompute(path: file.path, stat: file.stat)
        XCTAssertEqual(honest, expectedSHA256(of: Data("real-content".utf8)))
    }

    func testLookupOrComputeHandlesEmptyFile() throws {
        // SHA-256 of zero bytes is a well-known constant. Useful regression pin --
        // catches "I forgot to call finalize when the read loop body never ran."
        let file = try makeTempFile(bytes: Data())
        let hash = FileHashCache.shared.lookupOrCompute(path: file.path, stat: file.stat)
        XCTAssertEqual(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testLookupOrComputeHandlesLargerThanChunkSize() throws {
        // 200 KiB > 64 KiB streaming chunk. Exercises the multi-iteration read
        // loop and confirms the streaming hash matches the one-shot reference.
        let payload = Data(repeating: 0x7E, count: 200 * 1024)
        let file = try makeTempFile(bytes: payload)
        let hash = FileHashCache.shared.lookupOrCompute(path: file.path, stat: file.stat)
        XCTAssertEqual(hash, expectedSHA256(of: payload))
    }

    // MARK: - startLazyFill

    func testStartLazyFillPopulatesCacheEventually() throws {
        // The lazy fill is async on a userInitiated concurrent queue. The test
        // polls the cache for up to a few seconds before declaring a regression --
        // this matches how the NOTIFY_EXEC path waits for the AUTH_EXEC-side
        // fill to complete in production.
        let payload = Data("lazy-fill-content".utf8)
        let file = try makeTempFile(bytes: payload)
        let expected = expectedSHA256(of: payload)

        FileHashCache.shared.startLazyFill(path: file.path, stat: file.stat)

        let deadline = Date().addingTimeInterval(2)
        var got: String?
        while Date() < deadline {
            if let cached = FileHashCache.shared.lookup(stat: file.stat) {
                got = cached
                break
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertEqual(got, expected, "startLazyFill must populate the cache within the 2s deadline")
    }

    func testStartLazyFillIsNoOpWhenAlreadyCached() throws {
        // After lookupOrCompute primes the cache, a follow-up startLazyFill must
        // be a no-op -- the alreadyCached branch returns before dispatching. We
        // can't directly observe the no-dispatch, but we can confirm the cached
        // value is unchanged after the call.
        let payload = Data("already-cached".utf8)
        let file = try makeTempFile(bytes: payload)
        let expected = expectedSHA256(of: payload)
        XCTAssertEqual(FileHashCache.shared.lookupOrCompute(path: file.path, stat: file.stat), expected)
        FileHashCache.shared.startLazyFill(path: file.path, stat: file.stat)
        XCTAssertEqual(FileHashCache.shared.lookup(stat: file.stat), expected)
    }
}
