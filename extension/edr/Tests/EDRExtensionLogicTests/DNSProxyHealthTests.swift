// DNSProxyHealth tests: drive the watchdog with an injected clock so the sliding window and the bypass holds are
// deterministic. These pin the self-heal contract behind the DNS proxy's fail-open bypass (ADR-0014 /
// resilient-network-enforcement): a healthy proxy claims, a sustainedly-failing proxy bypasses to the system resolver, an
// active enforcement policy never open-bypasses, and the bypass LATCHES for a backing-off hold that is probed by a bounded
// number of flows rather than by every query that happens to arrive (issue #657).

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class DNSProxyHealthTests: XCTestCase {
    /// One row of the backoff table: the hold currently armed, the trip count the next failed probe produces, and the
    /// hold that trip arms.
    private struct BackoffStep {
        let armed: TimeInterval
        let trip: Int
        let next: TimeInterval
    }

    /// A movable monotonic clock (seconds) so tests advance time explicitly rather than sleeping. Matches the production
    /// seam, which is monotonic (ProcessInfo.systemUptime), not wall-clock.
    private final class FakeClock {
        var t: TimeInterval = 1_000_000
        func now() -> TimeInterval { t }
        func advance(_ seconds: TimeInterval) { t += seconds }
    }

    private func makeHealth(_ clock: FakeClock,
                            window: TimeInterval = 30,
                            minSamples: Int = 5,
                            failureRate: Double = 0.8,
                            maxSamples: Int = 256,
                            holdBase: TimeInterval = 30,
                            holdMax: TimeInterval = 300,
                            probeBudget: Int = 5,
                            probeTimeout: TimeInterval = 10) -> DNSProxyHealth {
        DNSProxyHealth(config: .init(window: window, minSamples: minSamples, failureRateToBypass: failureRate,
                                     maxSamples: maxSamples, bypassHoldBase: holdBase, bypassHoldMax: holdMax,
                                     probeClaimBudget: probeBudget, probeTimeout: probeTimeout),
                       now: clock.now)
    }

    /// Trip the watchdog into its first bypass and assert it got there. Most cases below start from this state.
    @discardableResult
    private func tripBypass(_ health: DNSProxyHealth, failures: Int = 5) -> DNSProxyHealth.Decision {
        for _ in 0..<failures { health.record(ok: false) }
        let decision = health.decide(policyActive: false)
        XCTAssertEqual(decision.verdict, .bypass)
        return decision
    }

    /// Advance past the hold and consume the probe's claim budget with the given outcome, returning the decision that
    /// settles the probe. Mirrors what the provider does: each claimed flow reports one forward outcome.
    @discardableResult
    private func runProbe(_ health: DNSProxyHealth, _ clock: FakeClock, hold: TimeInterval, ok: Bool,
                          budget: Int = 5) -> DNSProxyHealth.Decision {
        clock.advance(hold + 1)
        for _ in 0..<budget {
            XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
            health.record(ok: ok)
        }
        return health.decide(policyActive: false)
    }

    // MARK: Failure-rate accounting

    func testClaimsWhenNoSamples() {
        let clock = FakeClock()
        let health = makeHealth(clock)
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
    }

    func testClaimsBelowMinSamplesEvenIfAllFail() {
        let clock = FakeClock()
        let health = makeHealth(clock, minSamples: 5)
        // Four failures: under the min-samples floor, so the watchdog must not trip on a couple of stray failures.
        for _ in 0..<4 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
    }

    func testBypassesOnSustainedFailure() {
        let clock = FakeClock()
        let health = makeHealth(clock, minSamples: 5, failureRate: 0.8)
        for _ in 0..<5 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
    }

    func testStaysClaimingBelowFailureThreshold() {
        let clock = FakeClock()
        let health = makeHealth(clock, minSamples: 5, failureRate: 0.8)
        // 3 of 5 failed = 0.6, under the 0.8 bypass threshold: occasional timeouts are not an outage.
        health.record(ok: false); health.record(ok: false); health.record(ok: false)
        health.record(ok: true); health.record(ok: true)
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/sustained-failure-with-an-active-blocklist-does-not-open-bypass
    func testActivePolicyNeverBypasses() {
        let clock = FakeClock()
        let health = makeHealth(clock, minSamples: 5)
        for _ in 0..<10 { health.record(ok: false) }
        // Even though forwarding is fully wedged, an active enforcement policy forbids the open bypass (it would let a
        // blocked domain resolve via the system resolver). The proxy keeps claiming.
        XCTAssertEqual(health.decide(policyActive: true).verdict, .claim)
        // And the same state with no policy active does bypass, proving the policy flag is the only difference.
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
    }

    func testActivePolicyLeavesLatchStateIntact() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30)
        tripBypass(health)
        // A policy going active forces claiming, but must not clear the latch: when the policy clears mid-hold the
        // watchdog resumes bypassing rather than restarting the cycle with a fresh probe.
        XCTAssertEqual(health.decide(policyActive: true).verdict, .claim)
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transition: nil))
    }

    func testInvalidMinSamplesDoesNotProduceNaN() {
        let clock = FakeClock()
        // minSamples == 0 would, without the max(1, ...) clamp, pass the guard on an empty window and divide by zero.
        let health = makeHealth(clock, minSamples: 0)
        // Empty window: claim, no crash, no NaN-driven misbehavior.
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
        // With real failures the clamped floor still trips bypass exactly as a sane config would.
        for _ in 0..<5 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
    }

    func testSampleCapBoundsRetainedOutcomes() {
        let clock = FakeClock()
        // Cap at 10 within a generous window so the cap (not the window) is what bounds retention.
        let health = makeHealth(clock, window: 10_000, minSamples: 5, failureRate: 0.8, maxSamples: 10)
        // 100 successes then 10 failures, all inside the window. Without the cap the rate would be 10/110 = .09 (claim);
        // with the cap only the last 10 (all failures) are retained -> rate 1.0 -> bypass. Proves the cap drops oldest.
        for _ in 0..<100 { health.record(ok: true) }
        for _ in 0..<10 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
    }

    func testPartialWindowExpiryRecomputesRate() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5, failureRate: 0.8)
        // Five old failures at t0.
        for _ in 0..<5 { health.record(ok: false) }
        // 20s later, five successes. Window still holds all ten: 5/10 = 0.5 < 0.8 -> claim.
        clock.advance(20)
        for _ in 0..<5 { health.record(ok: true) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
        // 11s further (t0+31): the five old failures aged out, only the five successes remain -> still claim.
        clock.advance(11)
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
    }

    // MARK: Latch and hold

    // spec:extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/a-bypass-holds-before-the-upstream-is-probed-again
    func testBypassHoldsForTheWholeIntervalBeforeProbing() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5, holdBase: 30)
        XCTAssertEqual(tripBypass(health).transition, .enteredBypass(trip: 1, hold: 30))
        // The failure samples age out of the 30s window well before the hold expires, so walk up to the boundary in
        // steps: under the old "the window IS the cooldown" design the later of these would have resumed claiming.
        var elapsed = 0.0
        for _ in 0..<5 {
            clock.advance(5)
            elapsed += 5
            XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass,
                           "must still bypass \(elapsed)s into a 30s hold")
        }
        // And the hold does end: past 30s the watchdog probes rather than staying bypassed forever.
        clock.advance(6)
        XCTAssertEqual(health.decide(policyActive: false).transition, .startedProbe(trip: 1, budget: 5))
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/sustained-forwarding-failure-with-no-active-policy-bypasses-and-retries
    func testProbeStartsOnlyAfterTheHoldExpires() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, probeBudget: 5)
        tripBypass(health)
        clock.advance(29)
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transition: nil))
        clock.advance(2)
        // Past the hold: the watchdog opens a bounded restore attempt and this flow is the first probe claim.
        XCTAssertEqual(health.decide(policyActive: false),
                       .init(verdict: .claim, transition: .startedProbe(trip: 1, budget: 5)))
    }

    func testStaleOutcomesDuringTheHoldAreDiscarded() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, probeBudget: 5)
        tripBypass(health)
        // In-flight forwards that started before the trip land during the hold. They say nothing about the upstream's
        // state at probe time, so they must not be counted: if they were, these five successes would settle the probe
        // as healthy before a single probe flow was claimed.
        for _ in 0..<5 { health.record(ok: true) }
        clock.advance(31)
        XCTAssertEqual(health.decide(policyActive: false).transition, .startedProbe(trip: 1, budget: 5))
        // Still probing on the next flow (budget not spent, no outcomes yet), not resumed.
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transition: nil))
    }

    // MARK: Bounded probe

    // spec:extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/a-restore-attempt-claims-only-a-bounded-number-of-flows
    func testProbeClaimsAtMostItsBudgetAndBypassesTheRest() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, probeBudget: 3, probeTimeout: 10)
        tripBypass(health)
        clock.advance(31)
        // Exactly `budget` flows are conscripted into the probe...
        for _ in 0..<3 {
            XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
        }
        // ...and every further flow arriving while the probe is outstanding goes to the system resolver. This is the fix
        // for the incident: a restore attempt stalls at most `budget` client queries, not every query that arrives.
        for _ in 0..<20 {
            XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transition: nil))
        }
    }

    func testProbeBudgetIsRestoredForEachAttempt() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, probeBudget: 2, probeTimeout: 10)
        tripBypass(health)
        // Each failed attempt re-arms with a full budget, so the bound is per attempt and not a lifetime allowance.
        for (armedHold, nextTrip) in [(30.0, 2), (60.0, 3)] {
            let settle = runProbe(health, clock, hold: armedHold, ok: false, budget: 2)
            XCTAssertEqual(settle.transition, .enteredBypass(trip: nextTrip, hold: armedHold * 2))
        }
    }

    // MARK: Backoff

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/consecutive-failed-restore-attempts-extend-the-hold-up-to-a-cap
    func testConsecutiveFailedProbesDoubleTheHoldUpToTheCap() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, holdMax: 300)
        XCTAssertEqual(tripBypass(health).transition, .enteredBypass(trip: 1, hold: 30))
        // 30 -> 60 -> 120 -> 240 -> 300 (capped) -> 300. A wedged upstream costs a handful of probes over ~15 minutes
        // instead of the ~22 re-trips the un-latched watchdog produced in the same span. Each row is (the hold currently
        // armed, the trip the next failed probe produces, the hold it arms).
        let backoff = [
            BackoffStep(armed: 30, trip: 2, next: 60),
            BackoffStep(armed: 60, trip: 3, next: 120),
            BackoffStep(armed: 120, trip: 4, next: 240),
            BackoffStep(armed: 240, trip: 5, next: 300),
            BackoffStep(armed: 300, trip: 6, next: 300)
        ]
        for step in backoff {
            let settle = runProbe(health, clock, hold: step.armed, ok: false)
            XCTAssertEqual(settle.transition, .enteredBypass(trip: step.trip, hold: step.next),
                           "trip \(step.trip) must hold for \(step.next)s")
        }
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/a-healthy-restore-attempt-resumes-proxying-and-resets-the-hold
    func testHealthyProbeResumesAndResetsTheBackoff() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, holdMax: 300)
        tripBypass(health)
        // Two failed attempts push the hold to 120s...
        XCTAssertEqual(runProbe(health, clock, hold: 30, ok: false).transition, .enteredBypass(trip: 2, hold: 60))
        XCTAssertEqual(runProbe(health, clock, hold: 60, ok: false).transition, .enteredBypass(trip: 3, hold: 120))
        // ...then the upstream recovers and the next probe resumes proxying.
        XCTAssertEqual(runProbe(health, clock, hold: 120, ok: true), .init(verdict: .claim, transition: .resumed))
        // The backoff is reset: when the upstream wedges again later, that fresh trip holds for the base interval again,
        // not for 240s. Without the reset a host that flaps once an hour would creep to the cap and stay there. Advance
        // past the window first so the probe's successes age out, which is what a "later" re-wedge looks like.
        clock.advance(31)
        for _ in 0..<5 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).transition, .enteredBypass(trip: 1, hold: 30))
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/an-inconclusive-restore-attempt-re-arms-without-extending-the-hold
    func testInconclusiveProbeReArmsWithoutExtendingTheHold() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, probeBudget: 5, probeTimeout: 10)
        tripBypass(health)
        clock.advance(31)
        XCTAssertEqual(health.decide(policyActive: false).transition, .startedProbe(trip: 1, budget: 5))
        // The probe claims one flow that never reports an outcome (the client gave up, or the flow carried no datagram),
        // then the host goes quiet. Past the probe deadline the attempt is inconclusive.
        clock.advance(11)
        // Same trip count and the same 30s hold: an absence of traffic is not evidence the upstream is still wedged, so
        // it must not push an idle host toward the cap.
        XCTAssertEqual(health.decide(policyActive: false),
                       .init(verdict: .bypass, transition: .enteredBypass(trip: 1, hold: 30)))
    }

    func testProbeSettlesOnItsOwnFloorWhenTheBudgetIsBelowMinSamples() {
        let clock = FakeClock()
        // A budget smaller than the ordinary sample floor must still be judgeable, otherwise every probe would expire
        // inconclusive and the watchdog could never resume.
        let health = makeHealth(clock, minSamples: 5, holdBase: 30, probeBudget: 2, probeTimeout: 10)
        tripBypass(health)
        XCTAssertEqual(runProbe(health, clock, hold: 30, ok: true, budget: 2),
                       .init(verdict: .claim, transition: .resumed))
    }

    // MARK: Transition reporting

    func testTransitionIsReportedExactlyOncePerStateChange() {
        let clock = FakeClock()
        let health = makeHealth(clock, holdBase: 30, probeBudget: 5)
        // Healthy steady state: claim, no transition reported.
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transition: nil))
        for _ in 0..<5 { health.record(ok: false) }
        // Entry is reported once (the caller logs "entering bypass" here)...
        XCTAssertEqual(health.decide(policyActive: false),
                       .init(verdict: .bypass, transition: .enteredBypass(trip: 1, hold: 30)))
        // ...and not again on subsequent bypassed flows, so a per-flow log cannot flood during the hold.
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transition: nil))
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transition: nil))
        // Probe start is its own transition, distinct from entry: this is what makes one sustained bypass readable as
        // such in the log instead of looking like the re-trip loop of issue #657.
        clock.advance(31)
        XCTAssertEqual(health.decide(policyActive: false),
                       .init(verdict: .claim, transition: .startedProbe(trip: 1, budget: 5)))
        // Flows claimed inside the probe report no further transitions.
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transition: nil))
        for _ in 0..<5 { health.record(ok: true) }
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transition: .resumed))
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transition: nil))
    }
}
