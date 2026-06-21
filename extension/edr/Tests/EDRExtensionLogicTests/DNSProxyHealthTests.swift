// DNSProxyHealth tests: drive the watchdog with an injected clock so the sliding window is deterministic. These pin the
// self-heal contract behind the DNS proxy's fail-open bypass (ADR-0014 / resilient-network-enforcement): a healthy proxy
// claims, a sustainedly-failing proxy bypasses to the system resolver, an active enforcement policy never open-bypasses, and
// the bypass clears on its own once failures age out of the window (the window IS the cooldown).

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class DNSProxyHealthTests: XCTestCase {
    /// A movable clock so tests advance time explicitly rather than sleeping.
    private final class FakeClock {
        var t = Date(timeIntervalSince1970: 1_000_000)
        func now() -> Date { t }
        func advance(_ seconds: TimeInterval) { t = t.addingTimeInterval(seconds) }
    }

    private func makeHealth(_ clock: FakeClock,
                            window: TimeInterval = 30,
                            minSamples: Int = 5,
                            failureRate: Double = 0.8) -> DNSProxyHealth {
        DNSProxyHealth(config: .init(window: window, minSamples: minSamples, failureRateToBypass: failureRate),
                       now: clock.now)
    }

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

    func testFailuresAgeOutOfWindowEndingBypass() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5)
        for _ in 0..<5 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
        // While bypassing the proxy records nothing; the failures simply age out. Past the window they are gone, so the
        // watchdog probes again (claim). This is the self-heal: no explicit cooldown timer, the window is the cooldown.
        clock.advance(31)
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
    }

    func testRecoveryAfterProbeSucceeds() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5)
        for _ in 0..<5 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
        clock.advance(31) // old failures age out -> probe
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
        // Upstream recovered: probe queries succeed. The proxy stays claiming, no re-trip.
        for _ in 0..<5 { health.record(ok: true) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
    }

    func testReTripsIfStillWedgedAfterProbe() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5)
        for _ in 0..<5 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
        clock.advance(31)
        XCTAssertEqual(health.decide(policyActive: false).verdict, .claim)
        // Still wedged: the probe burst fails fast (via the proxy's forward deadline) and re-trips within minSamples.
        for _ in 0..<5 { health.record(ok: false) }
        XCTAssertEqual(health.decide(policyActive: false).verdict, .bypass)
    }

    func testTransitionFlagIsOneShotAcrossBypassEntryAndExit() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5)
        // Healthy steady state: claim, no transition reported.
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transitioned: false))
        for _ in 0..<5 { health.record(ok: false) }
        // First bypass decision reports the transition (the caller logs "entering bypass" once here)...
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transitioned: true))
        // ...and subsequent bypass decisions do NOT, so a per-flow log cannot flood during the bypass window.
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transitioned: false))
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .bypass, transitioned: false))
        // Failures age out: the exit back to claim reports the transition once (the caller logs "resuming").
        clock.advance(31)
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transitioned: true))
        XCTAssertEqual(health.decide(policyActive: false), .init(verdict: .claim, transitioned: false))
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
}
