// ApplicationControlStoreResyncTests covers the #322 epoch-axis recency gate and the application_control_resync event.
// Split out of ApplicationControlStoreTests so each class stays under SwiftLint's per-type / per-file length budgets; the
// shared store factory + JSON document builder live on AppControlStoreTestCase (AppControlStoreTestSupport.swift).

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class ApplicationControlStoreResyncTests: AppControlStoreTestCase {
    // MARK: apply: epoch-axis re-sync after a server policy-version regression (#322)

    // A server DB restore/reset regresses policy_version below what a host has persisted. The version-only gate would freeze
    // enforcement forever; the epoch axis (the policy's updated_at in microseconds) keeps advancing across the restore, so the
    // host re-syncs. This pins: baseline at a high version, then a LOWER version whose epoch advanced -> accepted, ruleset
    // replaced wholesale (the freeze is gone).
    // swiftlint:disable:next line_length
    func test_spec_extension_application_control_snapshot_is_the_source_of_truth_for_decisions_a_version_regression_with_a_newer_epoch_re_syncs_instead_of_freezing() {
        let store = makeStore()

        // Pre-restore baseline: high version, earlier epoch.
        store.apply(rawJSON: document(
            policyID: 1, version: 25,
            rules: [RuleSpec(type: "BINARY", identifier: "pre-restore", ruleID: "pre")],
            epoch: 1_000
        ))
        XCTAssertEqual(store.currentSnapshot().policyVersion, 25)

        // Post-restore push: version regressed to 2, but the operator's next mutation stamped a fresh (larger) updated_at.
        store.apply(rawJSON: document(
            policyID: 1, version: 2,
            rules: [RuleSpec(type: "BINARY", identifier: "post-restore", ruleID: "post")],
            epoch: 2_000
        ))
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyVersion, 2, "the lower post-restore version is accepted on the epoch axis")
        XCTAssertEqual(snapshot.policyEpoch, 2_000)
        XCTAssertNotNil(snapshot.binaryRules["post-restore"], "the post-restore ruleset now enforces")
        XCTAssertNil(snapshot.binaryRules["pre-restore"], "the stale ruleset is gone; enforcement is no longer frozen")
    }

    // The gate rejects only when BOTH axes are <= current. A snapshot that is older on version AND epoch is a genuine
    // duplicate / out-of-order replay (e.g. the newest-first command batch delivering an older entry after a newer one) and
    // must not regress the active ruleset.
    func testApplyRejectsSnapshotOlderOnBothAxes() {
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 1, version: 25,
            rules: [RuleSpec(type: "BINARY", identifier: "current", ruleID: "cur")],
            epoch: 2_000
        ))
        // Lower version AND lower epoch -> rejected.
        store.apply(rawJSON: document(
            policyID: 1, version: 2,
            rules: [RuleSpec(type: "BINARY", identifier: "older", ruleID: "old")],
            epoch: 1_000
        ))
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyVersion, 25, "older-on-both-axes apply must not regress the ruleset")
        XCTAssertEqual(snapshot.policyEpoch, 2_000)
        XCTAssertNil(snapshot.binaryRules["older"])
        XCTAssertNotNil(snapshot.binaryRules["current"])
    }

    // Backward-compat: a pre-#322 server (and any snapshot persisted before the field existed) carries no policy_epoch, which
    // decodes to 0. With both epochs at 0 the gate falls back to version-only behaviour: a regressed version is rejected, a
    // forward version is accepted. This guarantees the change is inert until the server also emits epochs.
    func testApplyWithoutEpochFallsBackToVersionOnlyGate() {
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 1, version: 25,
            rules: [RuleSpec(type: "BINARY", identifier: "baseline", ruleID: "base")]
        ))
        XCTAssertEqual(store.currentSnapshot().policyEpoch, 0, "absent policy_epoch decodes to the 0 sentinel")

        // Lower version, no epoch (both 0) -> rejected, exactly as before the fix.
        store.apply(rawJSON: document(
            policyID: 1, version: 2,
            rules: [RuleSpec(type: "BINARY", identifier: "regressed", ruleID: "reg")]
        ))
        XCTAssertEqual(store.currentSnapshot().policyVersion, 25, "no-epoch regression stays gated by version")
        XCTAssertNil(store.currentSnapshot().binaryRules["regressed"])

        // Higher version, no epoch -> accepted via the version axis.
        store.apply(rawJSON: document(
            policyID: 1, version: 26,
            rules: [RuleSpec(type: "BINARY", identifier: "forward", ruleID: "fwd")]
        ))
        XCTAssertEqual(store.currentSnapshot().policyVersion, 26)
        XCTAssertNotNil(store.currentSnapshot().binaryRules["forward"])
    }

    func test_spec_extension_application_control_application_control_re_sync_event_a_version_regression_emits_a_re_sync_event() {
        let store = makeStore()
        var reported: ApplicationControlResyncPayload?
        store.resyncReporter = { reported = $0 }

        store.apply(rawJSON: document(
            policyID: 1, version: 25,
            rules: [RuleSpec(type: "BINARY", identifier: "pre", ruleID: "pre")],
            epoch: 1_000
        ))
        store.apply(rawJSON: document(
            policyID: 1, version: 2,
            rules: [RuleSpec(type: "BINARY", identifier: "post", ruleID: "post")],
            epoch: 2_000
        ))

        let payload = try? XCTUnwrap(reported)
        XCTAssertEqual(payload?.policyID, 1)
        XCTAssertEqual(payload?.previousVersion, 25)
        XCTAssertEqual(payload?.newVersion, 2)
        XCTAssertEqual(payload?.previousEpoch, 1_000)
        XCTAssertEqual(payload?.newEpoch, 2_000)
        XCTAssertEqual(payload?.reason, "version_regression")
    }

    func test_spec_extension_application_control_application_control_re_sync_event_a_normal_forward_apply_emits_no_re_sync_event() {
        let store = makeStore()
        var fired = false
        store.resyncReporter = { _ in fired = true }

        // First apply (cold start) and a normal forward apply: version advances, epoch advances. Neither is a regression.
        store.apply(rawJSON: document(
            policyID: 1, version: 1,
            rules: [RuleSpec(type: "BINARY", identifier: "v1", ruleID: "r1")],
            epoch: 1_000
        ))
        store.apply(rawJSON: document(
            policyID: 1, version: 2,
            rules: [RuleSpec(type: "BINARY", identifier: "v2", ruleID: "r2")],
            epoch: 2_000
        ))
        XCTAssertFalse(fired, "a forward apply (version advancing) must not emit a re-sync event")
    }
}
