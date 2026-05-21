// ApplicationControlStore tests: exercise the snapshot-decode + per-rule-type
// routing + monotonic-version gate that the AUTH_EXEC decision engine relies on.
// ApplicationControlStore.shared is a singleton with a persistQueue.async that
// writes to /var/db/com.fleetdm.edr/application-control.json -- the test user
// has no write permission there, so the persist fails with a logged error and no
// real-world side effect. Each test below uses a UNIQUE policy_id high enough to
// not collide with anything any production / dev install would use, and an
// always-increasing version, so test method ordering does not matter.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class ApplicationControlStoreTests: XCTestCase {
    // MARK: - Helpers

    /// RuleSpec is a named record for the document() helper's `rules` argument.
    /// A 3-tuple would trip SwiftLint's large_tuple rule (max 2 members); a struct
    /// also reads better at the call sites and lets us name the field at use.
    private struct RuleSpec {
        let type: String
        let identifier: String
        let ruleID: String
    }

    /// document builds an ApplicationControlDocument as on-the-wire JSON bytes.
    private func document(policyID: Int64, version: Int64, rules: [RuleSpec]) -> Data {
        let ruleObjects = rules.map { rule in
            """
            {
              "rule_id": "\(rule.ruleID)",
              "rule_type": "\(rule.type)",
              "identifier": "\(rule.identifier)",
              "action": "BLOCK",
              "enforcement": "PROTECT",
              "severity": "high"
            }
            """
        }
        let joined = ruleObjects.joined(separator: ",")
        let json = """
        {
          "policy_id": \(policyID),
          "policy_version": \(version),
          "rules": [\(joined)]
        }
        """
        return Data(json.utf8)
    }

    // MARK: - ApplicationControlDocument decoder

    func testDocumentDecodesValidJSON() throws {
        let data = document(
            policyID: 7, version: 12,
            rules: [
                RuleSpec(type: "BINARY", identifier: String(repeating: "a", count: 64), ruleID: "r1"),
                RuleSpec(type: "TEAMID", identifier: "FDG8Q7N4CC", ruleID: "r2")
            ]
        )
        let decoded = try JSONDecoder().decode(ApplicationControlDocument.self, from: data)
        XCTAssertEqual(decoded.policyID, 7)
        XCTAssertEqual(decoded.policyVersion, 12)
        XCTAssertEqual(decoded.rules.count, 2)
        XCTAssertEqual(decoded.rules.first?.ruleID, "r1")
        XCTAssertEqual(decoded.rules.first?.action, "BLOCK")
    }

    // MARK: - apply: per-rule-type routing

    func testApplyRoutesEveryRuleTypeIntoItsOwnMap() {
        // Send one rule per type and verify each lands in the matching map. Uses a
        // policy_id (100001) far from any production value plus a high version so
        // the monotonic gate accepts even if a previous test set the same id.
        let payload = document(
            policyID: 100001, version: 1000,
            rules: [
                RuleSpec(type: "BINARY", identifier: "binary-hex", ruleID: "r1"),
                RuleSpec(type: "CDHASH", identifier: "cdhash-hex", ruleID: "r2"),
                RuleSpec(type: "SIGNINGID", identifier: "FDG8Q7N4CC:com.fleetdm.edr", ruleID: "r3"),
                RuleSpec(type: "CERTIFICATE", identifier: "cert-hex", ruleID: "r4"),
                RuleSpec(type: "TEAMID", identifier: "FDG8Q7N4CC", ruleID: "r5"),
                RuleSpec(type: "PATH", identifier: "/usr/local/bin/foo", ruleID: "r6")
            ]
        )
        ApplicationControlStore.shared.apply(rawJSON: payload)
        let snapshot = ApplicationControlStore.shared.currentSnapshot()
        // The store is a process-global singleton; assert policyID + policyVersion EXPLICITLY rather
        // than letting a wrong-state read silently fall through to no-op assertions. If a later test
        // ever leaves a higher version under this same policyID the monotonic gate would silently
        // reject this apply -- this XCTAssertEqual surfaces that as a loud failure instead.
        XCTAssertEqual(snapshot.policyID, 100001)
        XCTAssertEqual(snapshot.policyVersion, 1000)
        XCTAssertEqual(snapshot.binaryRules["binary-hex"]?.ruleID, "r1")
        XCTAssertEqual(snapshot.cdhashRules["cdhash-hex"]?.ruleID, "r2")
        XCTAssertEqual(snapshot.signingIDRules["FDG8Q7N4CC:com.fleetdm.edr"]?.ruleID, "r3")
        XCTAssertEqual(snapshot.certificateRules["cert-hex"]?.ruleID, "r4")
        XCTAssertEqual(snapshot.teamIDRules["FDG8Q7N4CC"]?.ruleID, "r5")
        XCTAssertEqual(snapshot.pathRules["/usr/local/bin/foo"]?.ruleID, "r6")
    }

    // MARK: - apply: monotonic-version gate

    func testApplyHonorsMonotonicVersionGate() {
        // Seed a baseline. Subsequent applies at policy_id 100002 with version <=
        // baseline must NOT regress the snapshot.
        let baseline = document(
            policyID: 100002, version: 500,
            rules: [RuleSpec(type: "BINARY", identifier: "baseline", ruleID: "baseline-rule")]
        )
        ApplicationControlStore.shared.apply(rawJSON: baseline)

        // Same id, older version -> rejected; the snapshot must keep the baseline.
        let older = document(
            policyID: 100002, version: 100,
            rules: [RuleSpec(type: "BINARY", identifier: "older", ruleID: "older-rule")]
        )
        ApplicationControlStore.shared.apply(rawJSON: older)

        var snapshot = ApplicationControlStore.shared.currentSnapshot()
        // After the rejected apply the baseline doc must still be the active snapshot. Pin
        // both: the older rule did NOT land AND the baseline rule still survives, so a future
        // bug where the older payload partially leaks (e.g. apply forgets to short-circuit
        // before swapping) would fail loudly here.
        XCTAssertEqual(snapshot.policyID, 100002)
        XCTAssertEqual(snapshot.policyVersion, 500)
        XCTAssertNil(snapshot.binaryRules["older"], "stale apply must not introduce its rules")
        XCTAssertNotNil(snapshot.binaryRules["baseline"], "baseline rule must survive rejected apply")

        // Same id, newer version -> accepted; the snapshot now reflects the new doc.
        let newer = document(
            policyID: 100002, version: 600,
            rules: [RuleSpec(type: "BINARY", identifier: "newer", ruleID: "newer-rule")]
        )
        ApplicationControlStore.shared.apply(rawJSON: newer)
        snapshot = ApplicationControlStore.shared.currentSnapshot()
        // Assert the policyID explicitly rather than hiding the rest of the assertions behind an
        // `if` guard -- a process-wide singleton means a different test's apply could land between
        // this `apply` and `currentSnapshot()`, and an `if`-gated block would silently no-op
        // through the failure. XCTAssertEqual surfaces it.
        XCTAssertEqual(snapshot.policyID, 100002)
        XCTAssertEqual(snapshot.policyVersion, 600)
        XCTAssertEqual(snapshot.binaryRules["newer"]?.ruleID, "newer-rule")
        // Wholesale replace: the baseline's rule is gone because the new doc's
        // rule list does not include it. Pinning this prevents a future bug
        // where apply() accidentally merges rather than replacing.
        XCTAssertNil(snapshot.binaryRules["baseline"], "newer doc must replace, not merge")
    }

    // MARK: - apply: malformed input

    func testApplyIgnoresMalformedJSON() {
        // Snapshot the policyVersion before the bad apply so we can confirm it
        // doesn't change. Using a sentinel policy_id keeps us insulated from other
        // tests' state.
        let beforeVersion = ApplicationControlStore.shared.currentSnapshot().policyVersion
        ApplicationControlStore.shared.apply(rawJSON: Data("{not json}".utf8))
        ApplicationControlStore.shared.apply(rawJSON: Data())
        let afterVersion = ApplicationControlStore.shared.currentSnapshot().policyVersion
        XCTAssertEqual(afterVersion, beforeVersion, "malformed JSON must not mutate snapshot state")
    }

    // MARK: - apply: unknown rule_type

    func testApplySkipsUnknownRuleTypeButLandsKnownOnes() {
        // FRUITCAKE is not a defined rule_type. The store logs a warning and skips
        // that entry but accepts the rest of the document, so a server-side
        // tagging mistake on a single rule does not break the entire snapshot.
        let payload = document(
            policyID: 100003, version: 1000,
            rules: [
                RuleSpec(type: "BINARY", identifier: "good-binary", ruleID: "good"),
                RuleSpec(type: "FRUITCAKE", identifier: "weird", ruleID: "weird")
            ]
        )
        ApplicationControlStore.shared.apply(rawJSON: payload)
        let snapshot = ApplicationControlStore.shared.currentSnapshot()
        // Same explicit-policyID-assertion rationale as testApplyRoutesEveryRuleTypeIntoItsOwnMap:
        // do not let a wrong-state singleton silently skip every check via an `if` guard.
        XCTAssertEqual(snapshot.policyID, 100003)
        XCTAssertEqual(snapshot.policyVersion, 1000)
        XCTAssertEqual(snapshot.binaryRules["good-binary"]?.ruleID, "good")
        // No bucket exists for FRUITCAKE; the weird identifier must not have
        // leaked into any of the six known maps.
        XCTAssertNil(snapshot.binaryRules["weird"])
        XCTAssertNil(snapshot.cdhashRules["weird"])
        XCTAssertNil(snapshot.signingIDRules["weird"])
        XCTAssertNil(snapshot.certificateRules["weird"])
        XCTAssertNil(snapshot.teamIDRules["weird"])
        XCTAssertNil(snapshot.pathRules["weird"])
    }

    // MARK: - empty snapshot constant

    func testEmptySnapshotHasNoRulesAndZeroPolicy() {
        // The static .empty is the cold-start state the store falls back to when
        // there's no persisted file on disk. Pinning the shape here so a future
        // tweak to the snapshot struct cannot quietly mint a non-empty default.
        let empty = ApplicationControlSnapshot.empty
        XCTAssertEqual(empty.policyID, 0)
        XCTAssertEqual(empty.policyVersion, 0)
        XCTAssertTrue(empty.binaryRules.isEmpty)
        XCTAssertTrue(empty.cdhashRules.isEmpty)
        XCTAssertTrue(empty.signingIDRules.isEmpty)
        XCTAssertTrue(empty.certificateRules.isEmpty)
        XCTAssertTrue(empty.teamIDRules.isEmpty)
        XCTAssertTrue(empty.pathRules.isEmpty)
    }
}
