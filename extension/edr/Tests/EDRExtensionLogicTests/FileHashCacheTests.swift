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

    // MARK: lookup

    func testLookupReturnsNilForUncachedFile() throws {
        let file = try makeTempFile(bytes: Data("lookup-cold".utf8))
        // First-time lookup must be a cache miss: lookup() does NOT trigger a fill,
        // it just reads the dictionary. The AUTH_EXEC fast path relies on this.
        XCTAssertNil(FileHashCache.shared.lookup(stat: file.stat))
    }

    // MARK: lookupOrCompute

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

    // MARK: startLazyFill

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

    // MARK: lookupOrComputeWithDeadline (issue #208)

    /// generousDeadlineMachAbs returns a mach absolute time several seconds in the future. Used by tests that want the
    /// sync compute path to run to completion against a normal-sized payload. mach_absolute_time + (seconds in ns) /
    /// (timebase numer/denom). Hardcoding the timebase ratio is fragile; we read it via mach_timebase_info to stay
    /// portable across hardware (the ratio is 1/1 on Apple Silicon but is different on Intel).
    private func generousDeadlineMachAbs(seconds: Double = 5) -> UInt64 {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        let nowMachAbs = mach_absolute_time()
        let offsetNs = UInt64(seconds * 1_000_000_000)
        let offsetMachAbs = offsetNs * UInt64(info.denom) / UInt64(info.numer)
        return nowMachAbs &+ offsetMachAbs
    }

    func testLookupOrComputeWithDeadlineReturnsComputedOnFirstCall() throws {
        let payload = Data("auth-exec-sync-hash".utf8)
        let file = try makeTempFile(bytes: payload)
        let expected = expectedSHA256(of: payload)

        let outcome = FileHashCache.shared.lookupOrComputeWithDeadline(
            path: file.path,
            stat: file.stat,
            deadlineMachAbs: generousDeadlineMachAbs()
        )
        XCTAssertEqual(outcome, .computed(expected))
        // Cache populated for the warm-case path.
        XCTAssertEqual(FileHashCache.shared.lookup(stat: file.stat), expected)
    }

    func testLookupOrComputeWithDeadlineReturnsCachedValueOnWarmHit() throws {
        // Pre-seed the cache via the no-deadline path, then call the deadline variant with a deadline that has already
        // expired. The cache hit must return .computed without doing any I/O; the deadlineExceeded branch must NOT fire
        // because the hash was already available before the budget was consulted.
        let payload = Data("warm-cache-hit".utf8)
        let file = try makeTempFile(bytes: payload)
        let expected = expectedSHA256(of: payload)
        XCTAssertEqual(FileHashCache.shared.lookupOrCompute(path: file.path, stat: file.stat), expected)

        let outcome = FileHashCache.shared.lookupOrComputeWithDeadline(
            path: file.path,
            stat: file.stat,
            deadlineMachAbs: 0
        )
        XCTAssertEqual(outcome, .computed(expected))
    }

    func testLookupOrComputeWithDeadlineReturnsDeadlineExceededOnZeroBudget() throws {
        // Cold cache + deadline already passed: the first deadline check between chunks fires immediately and the
        // helper returns .deadlineExceeded. The cache must stay empty so the next AUTH_EXEC retries the compute rather
        // than being served a partial / wrong hash.
        let payload = Data(repeating: 0x55, count: 128 * 1024) // >chunk size so the loop iterates at least twice
        let file = try makeTempFile(bytes: payload)

        let outcome = FileHashCache.shared.lookupOrComputeWithDeadline(
            path: file.path,
            stat: file.stat,
            deadlineMachAbs: 0
        )
        XCTAssertEqual(outcome, .deadlineExceeded)
        XCTAssertNil(FileHashCache.shared.lookup(stat: file.stat))
    }

    func testLookupOrComputeWithDeadlineReturnsReadFailedOnMissingFile() {
        // No file at this path -- the open-for-reading FileHandle path errors and we return .readFailed (distinct
        // from .deadlineExceeded so the audit event carries the right `reason` tag).
        var fakeStat = stat()
        fakeStat.st_dev = 1
        fakeStat.st_ino = 999_998
        fakeStat.st_mtimespec.tv_sec = 0
        fakeStat.st_mtimespec.tv_nsec = 0
        let path = "/tmp/edr-fileHashCacheTests-deadline-missing-\(UUID().uuidString)"

        let outcome = FileHashCache.shared.lookupOrComputeWithDeadline(
            path: path,
            stat: fakeStat,
            deadlineMachAbs: generousDeadlineMachAbs()
        )
        XCTAssertEqual(outcome, .readFailed)
    }

    // MARK: Sync hash drives the BINARY-rule decision (issue #208 close-out)
    //
    // These tests cross the FileHashCache → decideAuthExec boundary: the deadline-bounded sync SHA-256 produces the
    // HashOutcome that the pure decider consumes, and a BINARY rule keyed on that hash must DENY. This is the unit-level
    // proxy for the AUTH callback path (decideAndRespond in ESFSubscriber.swift, ESF-coupled and exercised at the system
    // layer): the cache + decider halves it composes are both in the SwiftPM target, so the cold-cache "first exec is
    // decided, not allowed" property is provable here without a live ES client.

    private func makeBinaryRule(identifier: String) -> ApplicationControlRule {
        ApplicationControlRule(
            ruleID: "app_control:binary-\(identifier.prefix(8))",
            ruleType: ApplicationControlRuleType.binary,
            identifier: identifier,
            action: ApplicationControlAction.block,
            enforcement: ApplicationControlEnforcement.protect,
            severity: "high",
            customMsg: nil,
            customURL: nil
        )
    }

    private func binaryOnlySnapshot(rule: ApplicationControlRule) -> ApplicationControlSnapshot {
        ApplicationControlSnapshot(
            policyID: 1, policyVersion: 1, deadlineFallback: .failClosed,
            binaryRules: [rule.identifier: rule],
            cdhashRules: [:], signingIDRules: [:], certificateRules: [:], teamIDRules: [:], pathRules: [:]
        )
    }

    // swiftlint:disable:next line_length
    func test_spec_extension_application_control_deadline_guarded_synchronous_sha_256_for_binary_rule_consultation_sync_hash_on_cold_cache_decides_the_first_exec() throws {
        // Cold cache: the binary has never been hashed. The deadline-bounded sync compute returns .computed within budget,
        // and a BINARY rule keyed on that exact SHA-256 must DENY on this FIRST exec (the #208 bypass was first-exec ALLOW).
        let payload = Data("cold-cache-first-exec-binary".utf8)
        let file = try makeTempFile(bytes: payload)
        let sha = expectedSHA256(of: payload)

        let outcome = FileHashCache.shared.lookupOrComputeWithDeadline(
            path: file.path, stat: file.stat, deadlineMachAbs: generousDeadlineMachAbs()
        )
        XCTAssertEqual(outcome, .computed(sha), "cold-cache sync compute must produce the hash within the deadline budget")

        let rule = makeBinaryRule(identifier: sha)
        let decision = decideAuthExec(
            tuple: AuthTuple(cdhash: nil, leafCertSHA256: nil, signingIDPrefixed: nil, teamID: nil, canonicalPath: nil),
            snapshot: binaryOnlySnapshot(rule: rule),
            hashOutcome: outcome
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: sha), "first exec of a BINARY-blocked target must DENY")
    }

    // swiftlint:disable:next line_length
    func test_spec_extension_application_control_deadline_guarded_synchronous_sha_256_for_binary_rule_consultation_mutated_dev_inode_mtime_does_not_bypass_the_binary_rule() throws {
        // Attacker mutates (dev,inode,mtime) on every exec to invalidate the cache key and keep returning to the cold path.
        // Each fresh key is a cache MISS that re-computes synchronously and yields .computed -> BINARY rule DENIES every time.
        // Model three successive "execs" of the same content under three distinct stat tuples (fresh temp files).
        let content = Data(repeating: 0x41, count: 4096)
        let sha = expectedSHA256(of: content)
        let rule = makeBinaryRule(identifier: sha)
        let snapshot = binaryOnlySnapshot(rule: rule)

        for attempt in 0..<3 {
            let file = try makeTempFile(bytes: content)
            let outcome = FileHashCache.shared.lookupOrComputeWithDeadline(
                path: file.path, stat: file.stat, deadlineMachAbs: generousDeadlineMachAbs()
            )
            XCTAssertEqual(outcome, .computed(sha), "fresh (dev,inode,mtime) must re-compute, not slip through (attempt \(attempt))")
            let decision = decideAuthExec(
                tuple: AuthTuple(cdhash: nil, leafCertSHA256: nil, signingIDPrefixed: nil, teamID: nil, canonicalPath: nil),
                snapshot: snapshot,
                hashOutcome: outcome
            )
            XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: sha), "every exec must DENY (attempt \(attempt))")
        }
    }

    func testLookupOrComputeWithDeadlineReturnsReadFailedOnInodeMismatch() throws {
        // Same TOCTOU guard as lookupOrCompute: if the opened FD's (dev, inode, mtime) differs from the expected
        // tuple, abort with .readFailed (treated as "hash unavailable, defer to posture") and leave the cache empty.
        let file = try makeTempFile(bytes: Data("real-content".utf8))
        var bogus = file.stat
        bogus.st_ino = file.stat.st_ino &+ 7777

        let outcome = FileHashCache.shared.lookupOrComputeWithDeadline(
            path: file.path,
            stat: bogus,
            deadlineMachAbs: generousDeadlineMachAbs()
        )
        XCTAssertEqual(outcome, .readFailed)
        XCTAssertNil(FileHashCache.shared.lookup(stat: bogus))
    }
}
