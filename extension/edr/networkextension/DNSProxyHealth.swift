import Foundation

/// DNSProxyHealth accounts upstream-forward outcomes over a sliding window and reports when DNS forwarding is
/// sustainedly failing. It is a REPORTER, not an actor: nothing it says changes whether a flow is claimed.
///
/// It used to be an actor, and that was the bug (issue #673). It told `handleNewFlow` to "bypass" by returning `false`,
/// on the premise that this hands resolution back to the system resolver. Apple documents the opposite:
///
///   "If the proxy implementation decides to not handle the flow and instead terminate it, the subclass implementation
///    of this method should return NO. ... In this case the flow is terminated."
///
/// Returning `false` TERMINATES the flow. There is no fallback path for a DNS proxy, because the proxy is the configured
/// resolver. Measured on edr-dev with a build that declined every flow: `dig` against either configured resolver returned
/// no answer, `dscacheutil` returned zero addresses, and `ping` could not resolve a name, while every one of those queries
/// succeeded the moment the DNS proxy configuration was disabled. The 2026-07-27 incident record agrees: the watchdog
/// fired 18 times, host DNS recovered in none of those windows, and only disabling the configuration restored it.
///
/// So the bypass, its latch, its backoff and its bounded probe are all gone. What survives is the measurement, because
/// knowing that forwarding is degraded is genuinely useful: it is the signal an operator needs, and the provider now
/// responds to a failing forward by retrying against another system resolver rather than by leaving the DNS path.
/// Surfacing this to agent health belongs with issue #649, which owns network-extension health reporting.
///
/// Pure Foundation, no NetworkExtension import, so the accounting is unit-testable without a live resolver. The clock is
/// injected (`now`) so tests drive the window deterministically, mirroring the agent's dropReporter seam.
final class DNSProxyHealth {
    /// Whether recent upstream forwarding is working.
    enum Status: Equatable {
        case healthy
        case degraded
    }

    struct Config {
        /// Sliding window over which forward outcomes are counted, so the rate reflects recent activity only.
        var window: TimeInterval = 30
        /// Minimum outcomes in the window before a verdict is meaningful. Guards against reporting degradation on one or
        /// two stray failures (a single unreachable resolver, a slow first query).
        var minSamples: Int = 5
        /// Failure fraction over the window at or above which forwarding is reported degraded. 0.8 means "4 of every 5
        /// recent forwards failed": a real outage, not the occasional benign timeout.
        var failureRateDegraded: Double = 0.8
        /// Hard cap on retained samples, so a high DNS query rate cannot make the per-forward prune / rate scans (run
        /// under the lock on the DNS hot path) grow unbounded. A few hundred recent forwards is a representative sample;
        /// older ones are dropped even if still inside the time window.
        var maxSamples: Int = 256
    }

    private let config: Config
    // Monotonic seconds, NOT wall-clock: the window is "recent activity", so it must be immune to NTP steps and manual
    // clock changes. Production uses ProcessInfo.systemUptime; tests inject a fake monotonic clock.
    private let now: () -> TimeInterval
    private let lock = NSLock()
    // Forward outcomes within the window, oldest first. `true` == upstream answered, `false` == failed or timed out.
    private var outcomes: [(at: TimeInterval, ok: Bool)] = []
    // Last reported status, so a change is reported once rather than on every forward. A per-forward line would be the
    // log flood the old watchdog already had to guard against: every DNS lookup produces at least one outcome.
    private var lastReported: Status = .healthy

    init(config: Config = Config(), now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.config = config
        self.now = now
    }

    /// record registers one upstream-forward outcome and returns the new status ONLY when it differs from the last
    /// reported one, so the caller logs a transition rather than a stream. Returns nil when nothing changed.
    ///
    /// Recording is the whole interface. There is deliberately no "should I claim this flow?" question to ask: the answer
    /// is always yes, because the alternative terminates the flow.
    @discardableResult
    func record(ok: Bool) -> Status? {
        lock.lock()
        defer { lock.unlock() }
        outcomes.append((at: now(), ok: ok))
        prune()

        let status = currentStatus()
        guard status != lastReported else { return nil }
        lastReported = status
        return status
    }

    /// status reports the current view without recording an outcome. Exposed for a future health poller (issue #649);
    /// it does not affect transition reporting.
    func status() -> Status {
        lock.lock()
        defer { lock.unlock() }
        prune()
        return currentStatus()
    }

    /// currentStatus is the pure failure-rate test over the window. Caller holds the lock.
    private func currentStatus() -> Status {
        // Clamp to >= 1 so a misconfigured minSamples (0 or negative) cannot pass the guard with an empty window and then
        // divide by zero into a NaN rate below.
        guard outcomes.count >= max(1, config.minSamples) else { return .healthy }
        let failures = outcomes.reduce(0) { $0 + ($1.ok ? 0 : 1) }
        return Double(failures) / Double(outcomes.count) >= config.failureRateDegraded ? .degraded : .healthy
    }

    /// prune drops samples older than the window, then enforces the maxSamples cap so the scans above stay bounded under
    /// a high query rate. Caller holds the lock; reads the monotonic clock once.
    private func prune() {
        let cutoff = now() - config.window
        if let firstFresh = outcomes.firstIndex(where: { $0.at >= cutoff }) {
            if firstFresh > 0 { outcomes.removeFirst(firstFresh) }
        } else {
            outcomes.removeAll(keepingCapacity: true)
        }
        let cap = max(1, config.maxSamples)
        if outcomes.count > cap { outcomes.removeFirst(outcomes.count - cap) }
    }
}
