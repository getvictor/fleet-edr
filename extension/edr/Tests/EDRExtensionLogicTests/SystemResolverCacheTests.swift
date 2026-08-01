// SystemResolverCache tests: the resolver lookup sits on the FAILURE path, so its cost matters most exactly when the
// host is unhealthy. These pin that a resolver outage cannot turn into one configd round trip per failing query.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class SystemResolverCacheTests: XCTestCase {
    private final class FakeClock {
        var t: TimeInterval = 1_000_000
        func now() -> TimeInterval { t }
        func advance(_ seconds: TimeInterval) { t += seconds }
    }

    /// Wait for an asynchronous refresh to publish, without sleeping a fixed amount.
    private func waitForRefresh(_ cache: SystemResolverCache, toEqual expected: [String]) {
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline, cache.addresses() != expected { usleep(2000) }
        XCTAssertEqual(cache.addresses(), expected)
    }

    func testPrimeFillsTheCacheSynchronously() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return ["192.168.1.1"] })
        // prime() runs at startProxy, off the DNS path, so the first failover of an outage never meets a cold cache.
        cache.prime()
        XCTAssertEqual(reads, 1)
        XCTAssertEqual(cache.addresses(), ["192.168.1.1"])
    }

    func testAddressesNeverBlocksOnACoolCache() {
        let clock = FakeClock()
        let started = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: {
            started.signal()
            release.wait()          // hold the "configd read" open
            return ["192.168.1.1"]
        })
        // This is the property that matters on the failure path: the caller returns immediately even while a read is in
        // flight. Blocking here would queue concurrent failing queries behind an XPC round trip.
        XCTAssertEqual(cache.addresses(), [], "a cold cache must return empty rather than wait for the read")
        XCTAssertEqual(started.wait(timeout: .now() + 2), .success, "the refresh must have been kicked off")
        release.signal()
        waitForRefresh(cache, toEqual: ["192.168.1.1"])
    }

    func testRepeatedReadsInsideTheTTLHitTheCache() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return ["192.168.1.1"] })
        cache.prime()
        // This is the outage shape: every query fails, so every query asks for the resolver list. Without the cache
        // each of these would be an XPC round trip to configd at the moment the host is already struggling.
        for _ in 0..<500 { _ = cache.addresses() }
        XCTAssertEqual(reads, 1, "a full-rate outage must cost one read, not one per query")
    }

    func testReadsAgainAfterTheTTLExpires() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return ["192.168.1.\(reads)"] })
        cache.prime()
        XCTAssertEqual(cache.addresses(), ["192.168.1.1"])
        clock.advance(4.9)
        XCTAssertEqual(cache.addresses(), ["192.168.1.1"], "still inside the TTL")
        XCTAssertEqual(reads, 1)
        // Past the TTL a refresh is kicked off. The stale value is served immediately (non-blocking) and the new one
        // lands shortly after, so a network change is picked up rather than pinned for the process lifetime.
        clock.advance(0.2)
        _ = cache.addresses()
        waitForRefresh(cache, toEqual: ["192.168.1.2"])
        XCTAssertEqual(reads, 2)
    }

    func testAnEmptyReadIsCachedRatherThanRetriedPerQuery() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return [] })
        cache.prime()
        // A host with no resolver list is exactly a host in trouble. Retrying the lookup per query would be the storm
        // this cache exists to prevent, so an empty answer must cache like any other.
        for _ in 0..<50 { XCTAssertTrue(cache.addresses().isEmpty) }
        XCTAssertEqual(reads, 1)
    }
}
