// ProviderLiveness tests: pin what the network extension tells the agent about which providers are actually capturing
// (issue #649). The XPC listener starts before the providers do, so "the agent connected" was never evidence of capture.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class ProviderLivenessTests: XCTestCase {
    func testStartsEmptySoNothingIsClaimedBeforeAProviderRuns() {
        let liveness = ProviderLiveness()
        // The report is empty at process start, which is the honest state: the listener is up, nothing is capturing yet.
        XCTAssertTrue(liveness.snapshot.isEmpty)
        XCTAssertFalse(liveness.anyRunning)
    }

    func testRecordsRunningAndStoppedProviders() {
        var liveness = ProviderLiveness()
        XCTAssertTrue(liveness.record(.contentFilter, .running))
        XCTAssertTrue(liveness.record(.dnsProxy, .running))
        XCTAssertEqual(liveness.snapshot, ["content_filter": "running", "dns_proxy": "running"])
        XCTAssertTrue(liveness.anyRunning)

        XCTAssertTrue(liveness.record(.dnsProxy, .stopped))
        XCTAssertEqual(liveness.snapshot, ["content_filter": "running", "dns_proxy": "stopped"])
    }

    func testRepeatingAStateIsNotATransition() {
        var liveness = ProviderLiveness()
        XCTAssertTrue(liveness.record(.contentFilter, .running))
        // The framework can deliver a start callback more than once; only real transitions should cost a broadcast.
        XCTAssertFalse(liveness.record(.contentFilter, .running))
    }

    func testForgetMakesAProviderAbsentRatherThanStopped() {
        var liveness = ProviderLiveness()
        liveness.record(.dnsProxy, .running)
        XCTAssertTrue(liveness.forget(.dnsProxy))
        // Absent, NOT stopped: the agent grades absence as opt-out and a stop as a fault, so a deliberately disabled
        // DNS proxy must vanish from the report rather than read as broken forever.
        XCTAssertTrue(liveness.snapshot.isEmpty)
        XCTAssertFalse(liveness.forget(.dnsProxy), "forgetting an absent provider is not a transition")
    }

    func testSessionLifecycleStopsAreAbsenceForEitherProvider() {
        // NEProviderStopReason raw values for "the session is going away or being replaced": superceded(11),
        // userLogout(12), userSwitch(13), configurationRemoved(10). Grading these as faults would report the extension
        // unhealthy on every logout and on every activation that supercedes the running configuration.
        for reason in [10, 11, 12, 13] {
            for provider in ProviderLiveness.Provider.allCases {
                XCTAssertTrue(
                    ProviderLiveness.isDeliberateAbsence(provider: provider, reason: reason),
                    "reason \(reason) is session lifecycle for \(provider.rawValue)"
                )
            }
        }
    }

    // spec:agent-status-reporting/network-extension-health-reflects-capture-provider-liveness/disabling-the-mandatory-content-filter-stays-visible
    func testOperatorDisablingIsAbsenceOnlyForTheOptInDNSProxy() {
        // userInitiated(1), providerDisabled(5), configurationDisabled(9): somebody switched this provider off.
        for reason in [1, 5, 9] {
            // DNS proxying is opt-in, so a host that turned it off is correctly configured, not degraded.
            XCTAssertTrue(
                ProviderLiveness.isDeliberateAbsence(provider: .dnsProxy, reason: reason),
                "reason \(reason) on the opt-in DNS proxy is a supported configuration"
            )
            // The content filter is not optional. An operator switching it off leaves the host with no network capture,
            // which is the tamper-adjacent state this component exists to surface, so it stays in the report as stopped.
            XCTAssertFalse(
                ProviderLiveness.isDeliberateAbsence(provider: .contentFilter, reason: reason),
                "reason \(reason) on the mandatory content filter must stay visible"
            )
        }
    }

    func testFaultsAreNeverAbsenceForEitherProvider() {
        // Including the shapes the 2026-07-17 incident produced: providerFailed(2), configurationFailed(7),
        // connectionFailed(14), and the unspecified none(0).
        for reason in [0, 2, 3, 4, 6, 7, 8, 14] {
            for provider in ProviderLiveness.Provider.allCases {
                XCTAssertFalse(
                    ProviderLiveness.isDeliberateAbsence(provider: provider, reason: reason),
                    "reason \(reason) is a fault for \(provider.rawValue)"
                )
            }
        }
    }

    func testProviderIdentifiersAreTheWireContract() {
        // The agent keys health on these exact strings, so a rename here is a wire break that would silently leave health
        // stuck rather than failing loudly.
        XCTAssertEqual(ProviderLiveness.Provider.contentFilter.rawValue, "content_filter")
        XCTAssertEqual(ProviderLiveness.Provider.dnsProxy.rawValue, "dns_proxy")
        XCTAssertEqual(ProviderLiveness.Provider.allCases.count, 2)
    }

    func testPayloadEncodesTheProviderMap() throws {
        let data = try JSONEncoder().encode(ProviderStatusPayload(providers: ["content_filter": "running"]))
        let decoded = try JSONDecoder().decode(ProviderStatusPayload.self, from: data)
        XCTAssertEqual(decoded.providers, ["content_filter": "running"])
        // The agent reads `payload.providers`; pin the key so a Swift-side rename cannot silently orphan the parser.
        let json = try XCTUnwrap(String(bytes: data, encoding: .utf8))
        XCTAssertTrue(json.contains("\"providers\""))
    }
}
