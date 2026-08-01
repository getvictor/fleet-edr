import Foundation
import os
import SystemConfiguration

/// SystemResolverCache vends the host's configured DNS resolver addresses to the failover path, cheaply.
///
/// Why a cache and a single session. The list is read from `SCDynamicStore`, which is an XPC round trip to `configd`,
/// and the read happens on the FAILURE path: when a resolver stops answering, EVERY query fails and every one of them
/// wants the list. A naive "create a session and copy a value per failover" is therefore not the rare operation it
/// looks like, it is one configd round trip per failing query at the exact moment the host is already unhealthy. The
/// session is created once and the result is cached for a short interval, so a resolver outage costs one read per TTL
/// rather than one per query.
///
/// Staleness is not a concern at this TTL. The value is only used to choose which resolver to retry against, and a few
/// seconds of staleness cannot pick a resolver that was never configured; it can at worst retry one that just went
/// away, which fails the same way the first attempt did.
///
/// Thread safety. `SCDynamicStore` is not documented as thread-safe and this is reached from concurrent `NWConnection`
/// completion closures, so both the cache and the underlying read are serialised by the lock.
///
/// The reader is injected so the caching, the TTL and the failure branch are unit-testable without touching `configd`.
final class SystemResolverCache {
    /// How long a read is reused. Short enough that a network change is picked up promptly, long enough that a
    /// full-rate outage cannot turn into a configd storm.
    private let ttl: TimeInterval
    // Monotonic, so an NTP step or a manual clock change cannot strand the cache. Matches DNSProxyHealth's seam.
    private let now: () -> TimeInterval
    private let read: () -> [String]
    private let lock = NSLock()
    private var cached: [String] = []
    private var readAt: TimeInterval?

    init(ttl: TimeInterval = 5,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         read: @escaping () -> [String] = SystemResolverCache.dynamicStoreReader()) {
        self.ttl = ttl
        self.now = now
        self.read = read
    }

    /// addresses returns the configured resolver addresses, reading through at most once per TTL.
    func addresses() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        let currentTime = now()
        if let readAt, currentTime - readAt < ttl { return cached }
        cached = read()
        readAt = currentTime
        return cached
    }

    /// dynamicStoreReader builds the production reader, creating the `SCDynamicStore` session ONCE and capturing it.
    /// Session creation is the expensive half of the operation, so it must not happen per read.
    ///
    /// Reads `State:/Network/Global/DNS`, the same key `scutil --dns` reports from. Deliberately NOT
    /// `NEDNSProxyProvider.systemDNSSettings`: measured on macOS 26.3 inside a running DNS proxy provider that returns
    /// nil while the host genuinely had two resolvers configured, so a failover built on it can never fire.
    static func dynamicStoreReader() -> () -> [String] {
        let store = SCDynamicStoreCreate(nil, "com.fleetdm.edr.networkextension" as CFString, nil, nil)
        return {
            guard let store,
                  let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any],
                  let servers = dns["ServerAddresses"] as? [String] else {
                return []
            }
            return servers
        }
    }
}
