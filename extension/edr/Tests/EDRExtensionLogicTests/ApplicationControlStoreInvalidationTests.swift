// ApplicationControlStoreInvalidationTests pins the onSnapshotApplied hook (#209): the store invokes it once on every
// accepted snapshot swap and never on a rejected (stale / duplicate) apply. ESFSubscriber wires that hook to
// es_clear_cache(client), so the cached-ALLOW optimisation cannot outlive a rule change. The flush itself needs
// EndpointSecurity and is exercised at the system / VM layer; this layer pins the trigger contract the store owns. Split into
// its own file so each ApplicationControlStore suite stays under SwiftLint's per-type / per-file length budgets.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class ApplicationControlStoreInvalidationTests: AppControlStoreTestCase {
    // The spec marker ID is a single unwrappable token; the resync suite disables the same rule for the same reason.
    // swiftlint:disable:next line_length
    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/replacing-the-active-snapshot-flushes-the-kernel-auth-cache
    func testHookFiresOnEveryAcceptedSwapAndNeverOnRejection() {
        let store = makeStore()
        var flushes = 0
        store.onSnapshotApplied = { flushes += 1 }

        // Initial accept: empty -> version 1. The swap happened, so the cache must be flushed.
        store.apply(rawJSON: document(
            policyID: 1, version: 1, rules: [RuleSpec(type: "BINARY", identifier: "a", ruleID: "a")], epoch: 1_000
        ))
        XCTAssertEqual(flushes, 1, "an accepted apply must flush the kernel cache")

        // Version advance: accepted -> flush.
        store.apply(rawJSON: document(
            policyID: 1, version: 2, rules: [RuleSpec(type: "BINARY", identifier: "b", ruleID: "b")], epoch: 1_000
        ))
        XCTAssertEqual(flushes, 2, "a version advance flushes")

        // Stale replay (older on both axes, same policy): rejected by the recency gate -> NO flush. A flush here would be
        // wasteful but harmless; asserting its absence pins that the hook tracks acceptance, not every inbound message.
        store.apply(rawJSON: document(
            policyID: 1, version: 1, rules: [RuleSpec(type: "BINARY", identifier: "stale", ruleID: "stale")], epoch: 500
        ))
        XCTAssertEqual(flushes, 2, "a rejected stale apply must not flush")

        // Epoch-only re-sync (version regressed, epoch advanced: the DB-restore signature): accepted -> flush. Broader than a
        // bare version bump, which is why the hook fires on acceptance rather than only on a version advance.
        store.apply(rawJSON: document(
            policyID: 1, version: 1, rules: [RuleSpec(type: "BINARY", identifier: "resync", ruleID: "resync")], epoch: 2_000
        ))
        XCTAssertEqual(flushes, 3, "an epoch-axis re-sync flushes")

        // Policy retarget (different policy_id): always accepted -> flush. A different ruleset is now active.
        store.apply(rawJSON: document(
            policyID: 2, version: 1, rules: [RuleSpec(type: "BINARY", identifier: "retarget", ruleID: "retarget")], epoch: 1
        ))
        XCTAssertEqual(flushes, 4, "a policy retarget flushes")
    }

    // A store with no hook wired (the no-enforcement embedding and any test that doesn't care) must apply snapshots normally:
    // the optional hook is purely additive and its absence never breaks the gate.
    func testApplyWithoutHookIsANoOp() {
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 1, version: 1, rules: [RuleSpec(type: "BINARY", identifier: "a", ruleID: "a")], epoch: 1_000
        ))
        XCTAssertEqual(store.currentSnapshot().policyVersion, 1, "apply must succeed with no onSnapshotApplied wired")
    }
}
