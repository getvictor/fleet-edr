import Foundation
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
/// The refresh is asynchronous, and that is the point. `addresses()` is called from an `NWConnection` completion closure
/// on the DNS failure path, so it must never block on an XPC round trip: a stale-but-present list is served immediately
/// and the refresh happens on a background queue. `prime()` fills the cache at proxy start so the first failover of an
/// outage, the one that matters most, never meets an empty cache.
///
/// Thread safety. `SCDynamicStore` is not documented as thread-safe and this is reached from concurrent `NWConnection`
/// completion closures, so the cache is serialised by a lock and the underlying read happens on one serial queue.
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
    private var refreshing = false
    /// One serial queue for the dynamic-store read, so the store is never touched concurrently and a refresh cannot
    /// pile up behind itself when many queries fail at once.
    private let refreshQueue = DispatchQueue(label: "com.fleetdm.edr.networkextension.resolvers")

    init(ttl: TimeInterval = 5,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         read: @escaping () -> [String] = SystemResolverCache.dynamicStoreReader()) {
        self.ttl = ttl
        self.now = now
        self.read = read
    }

    /// prime fills the cache synchronously. Called once from `startProxy`, off the DNS path, so that the first failover
    /// of an outage does not have to wait for a cold read.
    func prime() {
        refresh()
    }

    /// addresses returns the configured resolver addresses WITHOUT blocking.
    ///
    /// A stale list is served as-is while a refresh runs in the background. Staleness is harmless here: the value only
    /// chooses which resolver to retry against, and a few seconds of it can at worst name a resolver that just went
    /// away, which fails exactly as the first attempt did. Blocking, by contrast, would put an XPC round trip inside a
    /// connection completion on the failure path, where concurrent failing queries would queue behind it at the moment
    /// the host is already unhealthy.
    func addresses() -> [String] {
        let (value, stale) = lock.withLockValue { () -> ([String], Bool) in
            guard let readAt else { return (cached, true) }
            return (cached, now() - readAt >= ttl)
        }
        if stale { scheduleRefresh() }
        return value
    }

    /// scheduleRefresh kicks a background read, at most one at a time.
    private func scheduleRefresh() {
        let shouldStart = lock.withLockValue { () -> Bool in
            guard !refreshing else { return false }
            refreshing = true
            return true
        }
        guard shouldStart else { return }
        refreshQueue.async { [weak self] in self?.refresh() }
    }

    /// refresh performs the read and publishes the result. Runs on `refreshQueue` (or on the caller during `prime`),
    /// never with the lock held, so the XPC round trip cannot block another thread's `addresses()`.
    private func refresh() {
        let servers = read()
        let stamp = now()
        lock.withLockValue {
            cached = servers
            readAt = stamp
            refreshing = false
        }
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

private extension NSLock {
    /// withLockValue runs `body` under the lock and returns its result. Named to avoid colliding with the
    /// `withLock` that newer platforms vend, so the intent stays obvious at every call site above.
    func withLockValue<T>(_ body: () -> T) -> T {
        lock()
        defer { unlock() }
        return body()
    }
}
