import XCTest
@testable import EDRExtensionLogic

// Unit-test surface for the bounded preference-toggle subcommands (issue #905). Split out of HostAppExtensionManagerTests.swift
// to keep that file under SwiftLint's 500-line cap.

/// The bound itself (a dispatch watchdog wired into main.swift's top-level switch) is not reachable from this target,
/// because main.swift carries top-level executable code and is excluded from the SwiftPM logic library. What IS here is
/// the part that decides the outcome: the latch that makes the race between the framework's completion handler and the
/// watchdog single-valued, and the message the operator reads. Those are the two pieces that can be wrong silently.
final class PreferenceToggleBoundTests: XCTestCase {
    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-stalled-round-trip-fails-within-the-bound
    func testWatchdogClaimsTheLatchWhenTheRoundTripNeverCompletes() {
        let latch = PreferencesLatch()
        // Nothing completed, so the watchdog wins and the subcommand reports the timeout.
        XCTAssertTrue(latch.expire(), "the watchdog must be able to report when the round-trip never finished")
        XCTAssertFalse(latch.complete(), "a completion arriving after the timeout must be discarded, not reported")
    }

    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-completed-round-trip-is-unaffected
    func testCompletionClaimsTheLatchAndSilencesTheWatchdog() {
        let latch = PreferencesLatch()
        XCTAssertTrue(latch.complete(), "the round-trip's own result must be the one reported")
        XCTAssertFalse(latch.expire(), "the watchdog must stay silent once the round-trip has reported")
    }

    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-result-at-the-deadline-reports-once
    func testExactlyOneClaimWinsUnderConcurrency() {
        // The race is the reason the latch exists: the completion handler runs on a framework queue and the watchdog on
        // a timer queue, so a round-trip landing at the deadline has both arriving at once. A non-atomic check-then-set
        // passes a serial test and fails here.
        for _ in 0 ..< 200 {
            let latch = PreferencesLatch()
            let winners = NSMutableArray()
            let lock = NSLock()
            let group = DispatchGroup()
            for claim in [latch.complete, latch.expire] {
                group.enter()
                DispatchQueue.global().async {
                    let won = claim()
                    lock.lock(); if won { winners.add(true) }; lock.unlock()
                    group.leave()
                }
            }
            group.wait()
            XCTAssertEqual(winners.count, 1, "exactly one of complete/expire must win each race")
        }
    }

    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-result-at-the-deadline-reports-once
    func testOnlyTheWinnerReports() {
        // The defect this pins: claiming the latch on the way OUT, with the reporter call ahead of it, passes every latch test
        // above and still prints two outcomes. Ordering is the property, so the test has to observe whether the report ran.
        let latch = PreferencesLatch()
        var reported: [String] = []

        XCTAssertTrue(reportOnce(latch) { reported.append("round-trip") })
        XCTAssertEqual(reported, ["round-trip"])

        // The watchdog now loses, and must stay silent rather than appending a second outcome.
        XCTAssertFalse(reportOnce(latch) { reported.append("timeout") })
        XCTAssertEqual(reported, ["round-trip"], "the loser must not report")
    }

    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-result-at-the-deadline-reports-once
    func testTheWatchdogWinningSilencesTheRoundTrip() {
        let latch = PreferencesLatch()
        var reported: [String] = []

        XCTAssertTrue(latch.expire(), "the watchdog claims the outcome first")
        XCTAssertFalse(reportOnce(latch) { reported.append("round-trip") })
        XCTAssertEqual(reported, [], "a round-trip landing after the timeout must print nothing")
    }

    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-completed-round-trip-is-unaffected
    func testAnUnboundedChainReportsEveryLink() {
        // The regression this pins: `activate` chains enableContentFilter into enableDNSProxy in one process. A latch is
        // one-shot, so a single process-wide instance was claimed by the first link and the second lost every time, which
        // skipped its completion and left activation hung instead of exited. No watchdog is armed on that path, so there is
        // nothing to race: a nil latch must let every link report and continue.
        var reported: [String] = []
        XCTAssertTrue(reportOnce(nil) { reported.append("filter") })
        XCTAssertTrue(reportOnce(nil) { reported.append("dns") })
        XCTAssertEqual(reported, ["filter", "dns"], "an unbounded chain must not be silenced after its first link")
    }

    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-stalled-round-trip-fails-within-the-bound
    func testTimeoutMessageNamesTheSubcommandTheBoundAndTheRemedy() {
        let message = preferencesTimeoutMessage(for: .disableDNSProxy, timeout: defaultPreferencesTimeout)
        // Each assertion is a clause the requirement demands, so a message rewritten to drop one fails here rather than
        // leaving an operator on a wedged host with a bare "timed out".
        XCTAssertTrue(message.contains("disable-dns-proxy"), "must name the subcommand that timed out: \(message)")
        XCTAssertTrue(message.contains("\(Int(defaultPreferencesTimeout))s"), "must name the bound it exceeded: \(message)")
        XCTAssertTrue(message.contains("launchctl asuser"), "must give the console-session remedy: \(message)")
        XCTAssertTrue(message.hasPrefix("ERROR:"), "must read as a failure: \(message)")

        // The subcommand name is interpolated, not hardcoded, so every toggle names itself.
        for action in [HostAppAction.enableDNSProxy, .enableFilter, .disableFilter] {
            XCTAssertTrue(
                preferencesTimeoutMessage(for: action, timeout: defaultPreferencesTimeout).contains(action.rawValue),
                "\(action.rawValue) must name itself"
            )
        }
    }

    // spec:host-app-extension-manager/preference-toggles-are-bounded-and-fail-with-guidance/a-stalled-round-trip-fails-within-the-bound
    func testBoundIsLongEnoughForAHealthyRoundTripAndShortEnoughToAnswer() {
        // The floor is the load-bearing half. Saving a not-yet-approved configuration raises a console consent prompt and
        // does not return until a human answers, so a bound tight enough to "fail fast" would abort a supported
        // interactive flow. It must leave room to read a prompt and click Allow. The ceiling only keeps it a bound.
        XCTAssertGreaterThanOrEqual(defaultPreferencesTimeout, 60, "must not abort a human answering a consent prompt")
        XCTAssertLessThanOrEqual(defaultPreferencesTimeout, 180, "must still be a bound")
    }
}
