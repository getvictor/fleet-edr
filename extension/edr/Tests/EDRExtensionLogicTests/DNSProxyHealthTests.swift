// DNSProxyHealth tests: the watchdog is now a REPORTER, so these pin the accounting and the once-per-change reporting,
// not any claim/bypass decision (issue #673).
//
// What is deliberately NOT here any more: every test for the bypass, its latch, its backoff and its bounded probe. That
// machinery managed a mechanism that cannot work. Returning false from handleNewFlow is documented to terminate the flow
// ("In this case the flow is terminated"), and measurement agreed: with every flow declined, dig, dscacheutil and ping
// all failed to resolve, while the same queries succeeded the moment the proxy configuration was disabled.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class DNSProxyHealthTests: XCTestCase {
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
                            maxSamples: Int = 256) -> DNSProxyHealth {
        DNSProxyHealth(config: .init(window: window, minSamples: minSamples, failureRateDegraded: failureRate,
                                     maxSamples: maxSamples),
                       now: clock.now)
    }

    func testStartsHealthyAndStaysHealthyWithoutEnoughSamples() {
        let clock = FakeClock()
        let health = makeHealth(clock, minSamples: 5)
        XCTAssertEqual(health.status(), .healthy)
        // Four failures: under the floor, so the watchdog must not report degradation on a couple of stray failures.
        for _ in 0..<4 {
            XCTAssertNil(health.record(ok: false), "no change should be reported below the sample floor")
        }
        XCTAssertEqual(health.status(), .healthy)
    }

    // The spec marker ID is a single unwrappable token; disable line_length for it as the other marked suites do.
    // swiftlint:disable:next line_length
    // spec:extension-network-response/dns-proxy-reports-forwarding-degradation-without-leaving-the-dns-path/sustained-forwarding-failure-is-reported-as-degraded
    func testSustainedFailureIsReportedOnceAsDegraded() {
        let clock = FakeClock()
        let health = makeHealth(clock, minSamples: 5, failureRate: 0.8)
        for _ in 0..<4 { XCTAssertNil(health.record(ok: false)) }
        // The fifth failure crosses the floor and the rate threshold together.
        XCTAssertEqual(health.record(ok: false), .degraded)
        // Reported once: a per-forward line would be a log flood, since every lookup produces at least one outcome.
        for _ in 0..<10 { XCTAssertNil(health.record(ok: false)) }
        XCTAssertEqual(health.status(), .degraded)
    }

    func testRecoveryIsReportedOnce() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5)
        for _ in 0..<5 { _ = health.record(ok: false) }
        XCTAssertEqual(health.status(), .degraded)

        // Once the failures age out there is no recent evidence of failure left, so the very next outcome reports
        // recovery rather than waiting to re-accumulate a full sample floor. Prompt recovery is the point: an operator
        // should not keep seeing "degraded" for a window after forwarding started working again.
        clock.advance(31)
        XCTAssertEqual(health.record(ok: true), .healthy)
        // And reported once, not on every subsequent success.
        for _ in 0..<5 { XCTAssertNil(health.record(ok: true)) }
    }

    func testAFailedForwardNeverReportsRecovery() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5)
        for _ in 0..<5 { _ = health.record(ok: false) }
        XCTAssertEqual(health.status(), .degraded)

        // A traffic gap longer than the window empties the samples, so the window reads healthy for want of evidence.
        // The next forward still FAILS. Reporting "recovered" off that would hand an operator an all-clear in the middle
        // of an outage, which is the worst possible moment to be wrong.
        clock.advance(31)
        XCTAssertNil(health.record(ok: false), "a failed forward must never carry a recovery report")
        XCTAssertNil(health.record(ok: false))

        // Recovery still arrives, but only on a forward that actually worked.
        XCTAssertEqual(health.record(ok: true), .healthy)
    }

    func testOccasionalFailuresAreNotDegradation() {
        let clock = FakeClock()
        let health = makeHealth(clock, minSamples: 5, failureRate: 0.8)
        // 3 of 5 failed = 0.6, under the 0.8 threshold: occasional timeouts are not an outage.
        for ok in [false, false, false, true, true] {
            XCTAssertNil(health.record(ok: ok))
        }
        XCTAssertEqual(health.status(), .healthy)
    }

    func testFailuresAgeOutOfTheWindow() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5, failureRate: 0.8)
        for _ in 0..<5 { _ = health.record(ok: false) }
        XCTAssertEqual(health.status(), .degraded)
        // Past the window the samples are gone, so the status reverts even with no new traffic. Without this a host that
        // saw one bad minute would read degraded forever.
        clock.advance(31)
        XCTAssertEqual(health.status(), .healthy)
    }

    func testPartialWindowExpiryRecomputesRate() {
        let clock = FakeClock()
        let health = makeHealth(clock, window: 30, minSamples: 5, failureRate: 0.8)
        for _ in 0..<5 { _ = health.record(ok: false) }
        // 20s later, five successes. The window still holds all ten: 5/10 = 0.5 < 0.8 -> healthy.
        clock.advance(20)
        for _ in 0..<5 { _ = health.record(ok: true) }
        XCTAssertEqual(health.status(), .healthy)
        // 11s further: the old failures aged out, only the successes remain.
        clock.advance(11)
        XCTAssertEqual(health.status(), .healthy)
    }

    func testSampleCapBoundsRetainedOutcomes() {
        let clock = FakeClock()
        // Cap at 10 within a generous window so the cap (not the window) is what bounds retention.
        let health = makeHealth(clock, window: 10_000, minSamples: 5, failureRate: 0.8, maxSamples: 10)
        // 100 successes then 10 failures, all inside the window. Without the cap the rate would be 10/110 = .09
        // (healthy); with the cap only the last 10 (all failures) are retained -> rate 1.0 -> degraded. Proves the cap
        // drops oldest, which is what keeps the per-forward scans bounded on the DNS hot path.
        for _ in 0..<100 { _ = health.record(ok: true) }
        for _ in 0..<10 { _ = health.record(ok: false) }
        XCTAssertEqual(health.status(), .degraded)
    }

    func testInvalidMinSamplesDoesNotProduceNaN() {
        let clock = FakeClock()
        // minSamples == 0 would, without the max(1, ...) clamp, pass the guard on an empty window and divide by zero.
        let health = makeHealth(clock, minSamples: 0)
        XCTAssertEqual(health.status(), .healthy)
        for _ in 0..<5 { _ = health.record(ok: false) }
        XCTAssertEqual(health.status(), .degraded)
    }
}
