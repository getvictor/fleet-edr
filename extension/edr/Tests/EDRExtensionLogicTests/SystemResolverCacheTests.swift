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

    func testReadsThroughOnFirstUse() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return ["192.168.1.1"] })
        XCTAssertEqual(cache.addresses(), ["192.168.1.1"])
        XCTAssertEqual(reads, 1)
    }

    func testRepeatedReadsInsideTheTTLHitTheCache() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return ["192.168.1.1"] })
        // This is the outage shape: every query fails, so every query asks for the resolver list. Without the cache
        // each of these would be an XPC round trip to configd at the moment the host is already struggling.
        for _ in 0..<500 { _ = cache.addresses() }
        XCTAssertEqual(reads, 1, "a full-rate outage must cost one read, not one per query")
    }

    func testReadsAgainAfterTheTTLExpires() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return ["192.168.1.\(reads)"] })
        XCTAssertEqual(cache.addresses(), ["192.168.1.1"])
        clock.advance(4.9)
        XCTAssertEqual(cache.addresses(), ["192.168.1.1"], "still inside the TTL")
        XCTAssertEqual(reads, 1)
        // Past the TTL the list is re-read, so a network change is picked up rather than pinned for the process
        // lifetime.
        clock.advance(0.2)
        XCTAssertEqual(cache.addresses(), ["192.168.1.2"])
        XCTAssertEqual(reads, 2)
    }

    func testAnEmptyReadIsCachedRatherThanRetriedPerQuery() {
        let clock = FakeClock()
        var reads = 0
        let cache = SystemResolverCache(ttl: 5, now: clock.now, read: { reads += 1; return [] })
        // A host with no resolver list is exactly a host in trouble. Retrying the lookup per query would be the storm
        // this cache exists to prevent, so an empty answer must cache like any other.
        for _ in 0..<50 { XCTAssertTrue(cache.addresses().isEmpty) }
        XCTAssertEqual(reads, 1)
    }
}
