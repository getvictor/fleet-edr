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
/// The bypass LATCHES. An earlier design let the failure samples age out of the window and treated that as the cooldown, so
/// the proxy resumed claiming every flow roughly every 30s to probe the upstream. `handleNewFlow` has no dedicated probe
/// path, so each of those flows was pinned for the full forward deadline before failing open, and re-tripping needs
/// `minSamples` outcomes first. The host therefore oscillated instead of resolving: 18 bypass transitions in 11 minutes and
/// zero recovered name resolution during the 2026-07-27 incident (issue #657). The state machine below fixes that:
///
///   claiming --sustained failure--> bypassed(hold) --hold expires--> probing(budget) --+--healthy--> claiming
///                                        ^                                            |
///                                        +--still failing / inconclusive--------------+
///
/// A bypass holds for `bypassHoldBase`, doubling per consecutive failed probe up to `bypassHoldMax`, so a host whose upstream
/// stays wedged spends that time on the system resolver. A probe claims at most `probeClaimBudget` flows and bypasses the
/// rest, so restoring proxying costs a handful of stalled queries rather than every query that happens to arrive.
final class DNSProxyHealth {
    /// Verdict for a single `handleNewFlow` call. `.claim` => return `true` (the proxy resolves the flow). `.bypass` =>
    /// return `false` (the OS resolves via the system resolver).
    enum Verdict: Equatable {
        case claim
        case bypass
    }

    /// A state change, reported on the single `decide()` call that caused it so the caller logs it exactly once. A per-flow
    /// log would re-create the very log-flood this watchdog exists to prevent (every DNS lookup hits handleNewFlow), and
    /// distinguishing these three cases is what makes one sustained bypass readable as such instead of as a re-trip loop.
    enum Transition: Equatable {
        /// The proxy stopped claiming. `trip` is the consecutive-trip count (1 on the first), `hold` the interval it will
        /// bypass for before probing.
        case enteredBypass(trip: Int, hold: TimeInterval)
        /// The hold expired and the proxy is claiming up to `budget` flows to judge whether the upstream recovered.
        case startedProbe(trip: Int, budget: Int)
        /// A probe found the upstream healthy; the proxy is claiming normally again and the hold is back at its base.
        case resumed
    }

    /// Decision returned to handleNewFlow: the verdict plus the state change that this call caused, if any.
    struct Decision: Equatable {
        let verdict: Verdict
        let transition: Transition?
    }

    struct Config {
        /// Sliding window over which forward outcomes are counted, so the failure rate reflects recent activity only.
        var window: TimeInterval = 30
        /// Minimum outcomes in the window before the watchdog will trip. Guards against tripping on one or two stray
        /// failures (a single unreachable resolver, a slow first query).
        var minSamples: Int = 5
        /// Failure fraction over the window at or above which the proxy bypasses. 0.8 means "4 of every 5 recent forwards
        /// failed": a real outage, not the occasional benign timeout.
        var failureRateToBypass: Double = 0.8
        /// Hard cap on retained samples, so a high DNS query rate cannot make the per-forward prune / failure-rate scans
        /// (run under the lock on the DNS hot path) grow unbounded. A few hundred recent forwards is a representative
        /// failure-rate sample; older ones are dropped even if still inside the time window.
        var maxSamples: Int = 256
        /// How long the first bypass holds before probing. Long enough for the host to actually resolve names through the
        /// system resolver, short enough that a transient wedge costs little telemetry.
        var bypassHoldBase: TimeInterval = 30
        /// Ceiling on the doubling hold. A host whose upstream is wedged for an hour probes twelve times, not 120 times,
        /// and still recovers within five minutes of the upstream coming back.
        var bypassHoldMax: TimeInterval = 300
        /// How many flows a probe may claim. These are live client queries, so each one risks a forward-deadline stall:
        /// the budget is the blast radius of one restore attempt. Defaults to the failure-rate sample floor, which is the
        /// fewest outcomes that can produce a verdict.
        var probeClaimBudget: Int = 5
        /// How long a probe waits for its claimed flows to produce outcomes before giving up as inconclusive. Must exceed
        /// the proxy's per-forward deadline (3s), since a wedged upstream only reports failure once that deadline fires.
        var probeTimeout: TimeInterval = 10
    }

    /// Where the watchdog is in the trip / hold / probe cycle. `bypassed` and `probing` carry their own deadlines so the
    /// machine advances purely from the injected clock, with no timers to cancel.
    private enum State {
        case claiming
        case bypassed(until: TimeInterval)
        case probing(deadline: TimeInterval, claimsRemaining: Int)
    }

    private let config: Config
    // Monotonic seconds, NOT wall-clock: the window and the holds are "recent activity" and "time since", so they must be
    // immune to NTP steps and manual clock changes (a wall-clock jump would otherwise age samples out early or strand a
    // bypass for hours). Production uses ProcessInfo.systemUptime; tests inject a fake monotonic clock.
    private let now: () -> TimeInterval
    private let lock = NSLock()
    // Forward outcomes within the window, oldest first. `true` == upstream answered, `false` == failed or timed out.
    private var outcomes: [(at: TimeInterval, ok: Bool)] = []
    private var state: State = .claiming
    // Consecutive trips without an intervening healthy probe. Drives the hold doubling; reset by a healthy probe.
    private var consecutiveTrips = 0

    init(config: Config = Config(), now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.config = config
        self.now = now
    }

    /// record registers one upstream-forward outcome. Called from the proxy's forward completion / deadline paths.
    ///
    /// Outcomes are dropped while bypassed. The proxy claims nothing in that state, so anything arriving is an in-flight
    /// forward that started before the trip: counting it would let a stale failure decide the next probe, or (worse) a
    /// stale success mask a still-wedged upstream.
    func record(ok: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if case .bypassed = state { return }
        outcomes.append((at: now(), ok: ok))
        prune()
    }

    /// decide chooses whether the next flow should be claimed or bypassed, and reports the state change it caused (for
    /// one-shot transition logging). `policyActive` is the network-response enforcement switch (a domain blocklist or host
    /// containment ruleset): when an enforcement policy is active the watchdog MUST NOT open-bypass, because bypassing
    /// would let a blocked domain resolve via the system resolver. Until the network-response policy plane lands (deferred,
    /// see the resilient-network-enforcement proposal) the call site passes `false`, so this parameter is wired but always
    /// inert today. The latch state is left untouched while a policy forces claiming, so clearing the policy resumes the
    /// cycle where it left off rather than from a clean slate.
    func decide(policyActive: Bool) -> Decision {
        lock.lock()
        defer { lock.unlock() }
        prune()
        if policyActive {
            // Never silently allow a blocked domain to resolve. The spec's recovery for this case is rebuild-not-bypass;
            // the rebuild path ships with the enforcement policy plane, so for now we simply keep claiming.
            return Decision(verdict: .claim, transition: nil)
        }
        let transition = advance()
        return Decision(verdict: takeVerdict(), transition: transition)
    }

    /// advance runs the state machine for the current instant and returns the transition it produced, if any. Caller holds
    /// the lock. This is the only place `state` changes, so every transition is reported exactly once.
    private func advance() -> Transition? {
        switch state {
        case .claiming:
            return isSustainedlyFailing(minSamples: config.minSamples) ? enterBypass(extendHold: true) : nil
        case .bypassed(let until):
            return now() >= until ? startProbe() : nil
        case .probing(let deadline, _):
            // Enough outcomes to judge: the probe answered. Otherwise a probe that never drew traffic (or drew flows that
            // produced no forwards) expires as inconclusive and re-arms the SAME hold: absence of evidence must not push
            // an idle host toward the cap.
            let needed = probeVerdictSamples()
            if outcomes.count >= needed {
                return isSustainedlyFailing(minSamples: needed) ? enterBypass(extendHold: true) : resume()
            }
            return now() >= deadline ? enterBypass(extendHold: false) : nil
        }
    }

    /// takeVerdict maps the settled state to this flow's verdict, consuming one unit of probe budget when it claims.
    /// Caller holds the lock. A probe whose budget is spent bypasses while it waits for its claimed flows to report, so the
    /// number of client queries a restore attempt can stall is exactly `probeClaimBudget`.
    private func takeVerdict() -> Verdict {
        switch state {
        case .claiming:
            return .claim
        case .bypassed:
            return .bypass
        case .probing(let deadline, let claimsRemaining):
            guard claimsRemaining > 0 else { return .bypass }
            state = .probing(deadline: deadline, claimsRemaining: claimsRemaining - 1)
            return .claim
        }
    }

    /// enterBypass latches the bypass for the next hold interval. `extendHold` is false for an inconclusive probe, which
    /// learned nothing about the upstream and so must not count as a failed attempt. Caller holds the lock.
    private func enterBypass(extendHold: Bool) -> Transition {
        if extendHold { consecutiveTrips += 1 }
        let hold = holdInterval()
        state = .bypassed(until: now() + hold)
        // Drop the samples that produced this decision so the next probe is judged on its own outcomes alone.
        outcomes.removeAll(keepingCapacity: true)
        return .enteredBypass(trip: consecutiveTrips, hold: hold)
    }

    /// startProbe opens a bounded restore attempt. Caller holds the lock.
    private func startProbe() -> Transition {
        let budget = max(1, config.probeClaimBudget)
        state = .probing(deadline: now() + config.probeTimeout, claimsRemaining: budget)
        outcomes.removeAll(keepingCapacity: true)
        return .startedProbe(trip: consecutiveTrips, budget: budget)
    }

    /// resume returns to normal claiming after a healthy probe and resets the backoff. Caller holds the lock; the probe's
    /// successful outcomes are kept, so they count toward the window like any other recent activity.
    private func resume() -> Transition {
        consecutiveTrips = 0
        state = .claiming
        return .resumed
    }

    /// Growth factor applied to the hold per consecutive failed probe.
    private static let holdGrowthFactor: Double = 2
    /// Ceiling on the exponent, applied before the `pow` so a long-lived wedge cannot overflow the hold to infinity. The
    /// doublings past the configured cap are meaningless anyway: this many doublings of any sane base is far beyond it.
    private static let maxHoldDoublings = 30

    /// holdInterval grows per consecutive trip from the base, capped. Trip 1 holds for the base interval.
    private func holdInterval() -> TimeInterval {
        let base = max(0, config.bypassHoldBase)
        let cap = max(base, config.bypassHoldMax)
        let doublings = min(max(0, consecutiveTrips - 1), Self.maxHoldDoublings)
        return min(base * pow(Self.holdGrowthFactor, Double(doublings)), cap)
    }

    /// isSustainedlyFailing is the pure failure-rate test over the current window. `minSamples` is the floor below which
    /// the window is too thin to judge: the configured floor in the claiming state, the probe's own smaller floor during a
    /// restore attempt (a probe that can only claim 3 flows must still be judgeable on 3 outcomes). Caller holds the lock.
    private func isSustainedlyFailing(minSamples: Int) -> Bool {
        // Clamp to >= 1 so a misconfigured minSamples (0 or negative) cannot pass the guard with an empty window and then
        // divide by zero into a NaN failure rate below.
        guard outcomes.count >= max(1, minSamples) else { return false }
        let failures = outcomes.reduce(0) { $0 + ($1.ok ? 0 : 1) }
        return Double(failures) / Double(outcomes.count) >= config.failureRateToBypass
    }

    /// probeVerdictSamples is how many outcomes a probe needs before it can be judged: the claim budget, but never more
    /// than the ordinary sample floor, so a budget larger than `minSamples` does not make a probe wait for outcomes the
    /// failure-rate test would not require.
    private func probeVerdictSamples() -> Int {
        max(1, min(config.probeClaimBudget, config.minSamples))
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
