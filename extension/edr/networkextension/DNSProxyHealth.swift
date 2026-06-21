import Foundation

/// DNSProxyHealth is the self-heal watchdog for the DNS proxy. An `NEDNSProxyProvider` that returns `true` from
/// `handleNewFlow` becomes the sole resolver for the host: once it claims a flow the operating system does not resolve it
/// anywhere else, so an upstream-forwarding wedge takes down ALL name resolution while ICMP and direct-IP traffic keep
/// working. That is the 2026-06-20 incident (974 `Upstream UDP connection failed` errors clustered in one minute, only a
/// reboot cleared it). This type lets the proxy fail open: it accounts upstream-forward outcomes over a sliding time window
/// and, when forwarding is sustainedly failing, tells `handleNewFlow` to BYPASS (return `false`) so the OS hands resolution
/// back to the system resolver. Bypassing costs `dns_query` telemetry for the bypass window, which is the correct trade for a
/// monitoring tap (observation fails open; see ADR-0014).
///
/// Pure Foundation, no NetworkExtension import, so the decision logic is unit-testable without a live resolver. The clock is
/// injected (`now`) so tests drive the window deterministically, mirroring the agent's dropReporter seam.
///
/// Self-heal without extra state: the failure window is time-based, so while bypassing the proxy records nothing and the old
/// failure samples simply age out. Once they do, `verdict` returns `.claim` again, which probes the upstream; if it is still
/// wedged the probe queries fail (fast, via the proxy's forward deadline) and re-trip the bypass within `minSamples`; if it
/// recovered the probe succeeds and the proxy stays claiming. No explicit cooldown timer is needed: the window IS the cooldown.
final class DNSProxyHealth {
    /// Verdict for a single `handleNewFlow` call. `.claim` => return `true` (the proxy resolves the flow). `.bypass` =>
    /// return `false` (the OS resolves via the system resolver).
    enum Verdict: Equatable {
        case claim
        case bypass
    }

    /// Decision returned to handleNewFlow: the verdict plus whether it flipped from the previously-returned value.
    /// `transitioned` lets the caller log the bypass entry/exit exactly once instead of on every flow. A per-flow log
    /// would re-create the very log-flood this watchdog exists to prevent (every DNS lookup hits handleNewFlow).
    struct Decision: Equatable {
        let verdict: Verdict
        let transitioned: Bool
    }

    struct Config {
        /// Sliding window over which forward outcomes are counted. Old samples age out, which is also what ends a bypass.
        var window: TimeInterval = 30
        /// Minimum outcomes in the window before the watchdog will trip. Guards against tripping on one or two stray
        /// failures (a single unreachable resolver, a slow first query) and bounds the probe burst when re-tripping.
        var minSamples: Int = 5
        /// Failure fraction over the window at or above which the proxy bypasses. 0.8 means "4 of every 5 recent forwards
        /// failed": a real outage, not the occasional benign timeout.
        var failureRateToBypass: Double = 0.8
        /// Hard cap on retained samples, so a high DNS query rate cannot make the per-forward prune / failure-rate scans
        /// (run under the lock on the DNS hot path) grow unbounded. A few hundred recent forwards is a representative
        /// failure-rate sample; older ones are dropped even if still inside the time window.
        var maxSamples: Int = 256
    }

    private let config: Config
    // Monotonic seconds, NOT wall-clock: the window is "recent activity", so it must be immune to NTP steps and manual
    // clock changes (a wall-clock jump would otherwise age samples out early or make them linger, distorting when the
    // bypass clears). Production uses ProcessInfo.systemUptime; tests inject a fake monotonic clock.
    private let now: () -> TimeInterval
    private let lock = NSLock()
    // Forward outcomes within the window, oldest first. `true` == upstream answered, `false` == failed or timed out.
    private var outcomes: [(at: TimeInterval, ok: Bool)] = []
    // The verdict last returned by decide(), for one-shot transition logging. Starts .claim (the proxy claims by default),
    // so the first decide() does not report a spurious transition.
    private var lastVerdict: Verdict = .claim

    init(config: Config = Config(), now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.config = config
        self.now = now
    }

    /// record registers one upstream-forward outcome. Called from the proxy's forward completion / deadline paths.
    func record(ok: Bool) {
        lock.lock()
        defer { lock.unlock() }
        outcomes.append((at: now(), ok: ok))
        prune()
    }

    /// decide chooses whether the next flow should be claimed or bypassed, and reports whether that flips the previous
    /// verdict (for one-shot transition logging). `policyActive` is the network-response enforcement switch (a domain
    /// blocklist or host-containment ruleset): when an enforcement policy is active the watchdog MUST NOT open-bypass,
    /// because bypassing would let a blocked domain resolve via the system resolver. Until the network-response policy
    /// plane lands (deferred, see the resilient-network-enforcement proposal) the call site passes `false`, so this
    /// parameter is wired but always inert today.
    func decide(policyActive: Bool) -> Decision {
        lock.lock()
        defer { lock.unlock() }
        prune()
        let verdict = computeVerdict(policyActive: policyActive)
        let transitioned = verdict != lastVerdict
        lastVerdict = verdict
        return Decision(verdict: verdict, transitioned: transitioned)
    }

    /// computeVerdict is the pure decision, caller holds the lock.
    private func computeVerdict(policyActive: Bool) -> Verdict {
        if policyActive {
            // Never silently allow a blocked domain to resolve. The spec's recovery for this case is rebuild-not-bypass;
            // the rebuild path ships with the enforcement policy plane, so for now we simply keep claiming.
            return .claim
        }
        // Clamp to >= 1 so a misconfigured minSamples (0 or negative) cannot pass the guard with an empty window and then
        // divide by zero into a NaN failure rate below.
        let minSamples = max(1, config.minSamples)
        guard outcomes.count >= minSamples else { return .claim }
        let failures = outcomes.reduce(0) { $0 + ($1.ok ? 0 : 1) }
        let failureRate = Double(failures) / Double(outcomes.count)
        return failureRate >= config.failureRateToBypass ? .bypass : .claim
    }

    /// prune drops samples older than the window, then enforces the maxSamples cap so the scans above stay bounded under a
    /// high query rate. Caller holds the lock; reads the monotonic clock once.
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
