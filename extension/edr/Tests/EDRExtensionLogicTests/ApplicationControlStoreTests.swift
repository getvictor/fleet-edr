// ApplicationControlStore tests: exercise the snapshot-decode + per-rule-type
// routing + monotonic-version gate + persist/load round-trip the AUTH_EXEC
// decision engine relies on.
//
// Each test builds its OWN ApplicationControlStore via makeStore() with a temp
// storagePath under FileManager.default.temporaryDirectory. That gives every
// test method:
//
//   1. A fresh ApplicationControlSnapshot.empty starting state -- no cross-test
//      contamination via the process-global .shared singleton.
//   2. An isolated on-disk policy file that addTeardownBlock removes when the
//      test finishes, so the async persist no longer writes against (or fails
//      against) /var/db/com.fleetdm.edr/application-control.json.
//
// The unique-policy-id-per-test gymnastics the previous revision needed are
// gone. Policy IDs can be 1, 2, 3 -- whatever reads cleanly -- because each
// store starts empty. ApplicationControlStore.shared is NOT touched by any of
// these tests.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class ApplicationControlStoreTests: XCTestCase {
    // MARK: Helpers

    /// RuleSpec is a named record for the document() helper's `rules` argument.
    /// A 3-tuple would trip SwiftLint's large_tuple rule (max 2 members); a struct
    /// also reads better at the call sites and lets us name the field at use.
    private struct RuleSpec {
        let type: String
        let identifier: String
        let ruleID: String
    }

    /// makeStore returns a fresh ApplicationControlStore with a temp on-disk
    /// policy path. The path is unique per call so concurrent / parallelized
    /// test runs cannot stomp each other's persist files. The teardown block
    /// removes the file (and any parent directory the persist code created).
    private func makeStore() -> ApplicationControlStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppControlTests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("application-control.json")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }
        return ApplicationControlStore(storagePath: url.path)
    }

    /// waitForFile polls for the file at `path` to exist within `deadline`. The
    /// store's persistQueue is private, so we cannot synchronize on it directly;
    /// the file-exists predicate is what the apply→persist→load round-trip test
    /// needs to gate on before loading the snapshot back from disk. 2s is the
    /// same budget testStartLazyFillPopulatesCacheEventually uses for the same
    /// pattern.
    @discardableResult
    private func waitForFile(at path: String, deadline: TimeInterval = 2) -> Bool {
        let stop = Date().addingTimeInterval(deadline)
        while Date() < stop {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return FileManager.default.fileExists(atPath: path)
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

    // MARK: ApplicationControlDocument decoder

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

    // MARK: apply: per-rule-type routing

    // spec:endpoint-event-collection/process-exec-authorization/an-exec-of-a-blocklisted-path-is-denied
    //
    // The exec-authorization decision is "look up the exec's path / cdhash / signing-id / team-id in
    // the per-rule-type maps the ApplicationControlStore maintains, and DENY if any rule matches."
    // This test pins the store-side half of that decision: every rule type lands in its own typed map
    // and is indexed by the identifier the subscriber consults at exec-authorization time. The ESF
    // ES_AUTH_RESULT_DENY return from the subscriber when the store reports a match is downstream of
    // this test (subscribed in extension/ESFSubscriber.swift, not unit-tested here), but the data
    // structure that drives the deny decision is what the assertions below pin.
    func testApplyRoutesEveryRuleTypeIntoItsOwnMap() {
        let store = makeStore()
        let payload = document(
            policyID: 1, version: 1,
            rules: [
                RuleSpec(type: "BINARY", identifier: "binary-hex", ruleID: "r1"),
                RuleSpec(type: "CDHASH", identifier: "cdhash-hex", ruleID: "r2"),
                RuleSpec(type: "SIGNINGID", identifier: "FDG8Q7N4CC:com.fleetdm.edr", ruleID: "r3"),
                RuleSpec(type: "CERTIFICATE", identifier: "cert-hex", ruleID: "r4"),
                RuleSpec(type: "TEAMID", identifier: "FDG8Q7N4CC", ruleID: "r5"),
                RuleSpec(type: "PATH", identifier: "/usr/local/bin/foo", ruleID: "r6")
            ]
        )
        store.apply(rawJSON: payload)
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 1)
        XCTAssertEqual(snapshot.policyVersion, 1)
        XCTAssertEqual(snapshot.binaryRules["binary-hex"]?.ruleID, "r1")
        XCTAssertEqual(snapshot.cdhashRules["cdhash-hex"]?.ruleID, "r2")
        XCTAssertEqual(snapshot.signingIDRules["FDG8Q7N4CC:com.fleetdm.edr"]?.ruleID, "r3")
        XCTAssertEqual(snapshot.certificateRules["cert-hex"]?.ruleID, "r4")
        XCTAssertEqual(snapshot.teamIDRules["FDG8Q7N4CC"]?.ruleID, "r5")
        XCTAssertEqual(snapshot.pathRules["/usr/local/bin/foo"]?.ruleID, "r6")
    }

    // spec:endpoint-event-collection/process-exec-authorization/an-exec-of-a-non-blocklisted-path-is-allowed
    //
    // The exec-authorization decision is "look up the exec's path / cdhash / signing-id / team-id / binary
    // hash in the per-rule-type maps the ApplicationControlStore maintains, and DENY if any rule matches;
    // ALLOW (and emit a notification event) otherwise." The blocklisted-path-is-denied scenario is pinned by
    // testApplyRoutesEveryRuleTypeIntoItsOwnMap (data structure side of the deny decision); this test pins
    // the symmetric allow case: a path / identifier that is NOT in the typed maps produces no lookup hit, so
    // the subscriber's downstream `if storeRule == nil { return ES_AUTH_RESULT_ALLOW }` branch takes the
    // allow path. The ES_AUTH_RESULT_ALLOW return + the resulting exec notification event are downstream of
    // this test (subscribed in extension/ESFSubscriber.swift, exercised at the system / VM layer per
    // docs/testing-strategy.md), but the absence-of-match in the data structure is the unit-testable half.
    func testApplySnapshotMissesUnregisteredIdentifiers() {
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 1, version: 1,
            rules: [
                RuleSpec(type: "BINARY", identifier: "blocked-binary-hex", ruleID: "r1"),
                RuleSpec(type: "PATH", identifier: "/usr/local/bin/banned", ruleID: "r2"),
                RuleSpec(type: "SIGNINGID", identifier: "BANNED:com.example.banned", ruleID: "r3"),
                RuleSpec(type: "TEAMID", identifier: "BANNEDTEAM", ruleID: "r4")
            ]
        ))
        let snapshot = store.currentSnapshot()
        // Sanity-check the blocked entries DID land so the negative assertions below are meaningful.
        XCTAssertNotNil(snapshot.binaryRules["blocked-binary-hex"])
        XCTAssertNotNil(snapshot.pathRules["/usr/local/bin/banned"])
        // The same-typed-map lookup misses for an identifier the policy never named. The
        // ApplicationControlStore returns no rule; the subscriber's "no match -> allow" branch fires.
        XCTAssertNil(snapshot.binaryRules["unregistered-binary-hex"])
        XCTAssertNil(snapshot.pathRules["/usr/bin/ls"])
        XCTAssertNil(snapshot.signingIDRules["FDG8Q7N4CC:com.fleetdm.allowed"])
        XCTAssertNil(snapshot.teamIDRules["FDG8Q7N4CC"])
        // Cross-type lookups also miss: a path that happens to coincide with a binary-hex string lands in
        // the wrong map by construction (each rule type's identifier shape is distinct). This pins the
        // "every rule type is consulted independently" property.
        XCTAssertNil(snapshot.binaryRules["/usr/local/bin/banned"])
        XCTAssertNil(snapshot.pathRules["blocked-binary-hex"])
    }

    // MARK: apply: monotonic-version gate

    func test_spec_extension_application_control_snapshot_is_the_source_of_truth_for_decisions_a_stale_snapshot_is_rejected() {
        let store = makeStore()

        // Baseline at version 500.
        store.apply(rawJSON: document(
            policyID: 1, version: 500,
            rules: [RuleSpec(type: "BINARY", identifier: "baseline", ruleID: "baseline-rule")]
        ))

        // Same id, older version -> rejected; the baseline must survive.
        store.apply(rawJSON: document(
            policyID: 1, version: 100,
            rules: [RuleSpec(type: "BINARY", identifier: "older", ruleID: "older-rule")]
        ))
        var snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 1)
        XCTAssertEqual(snapshot.policyVersion, 500, "older-version apply must not advance policyVersion")
        XCTAssertNil(snapshot.binaryRules["older"], "stale apply must not introduce its rules")
        XCTAssertNotNil(snapshot.binaryRules["baseline"], "baseline rule must survive rejected apply")

        // Same id, equal version -> rejected (gate is strictly greater).
        store.apply(rawJSON: document(
            policyID: 1, version: 500,
            rules: [RuleSpec(type: "BINARY", identifier: "equal", ruleID: "equal-rule")]
        ))
        snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyVersion, 500, "equal-version apply must be a no-op")
        XCTAssertNil(snapshot.binaryRules["equal"])
        XCTAssertNotNil(snapshot.binaryRules["baseline"])

        // Same id, newer version -> accepted; the snapshot now reflects the new doc.
        store.apply(rawJSON: document(
            policyID: 1, version: 600,
            rules: [RuleSpec(type: "BINARY", identifier: "newer", ruleID: "newer-rule")]
        ))
        snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyVersion, 600)
        XCTAssertEqual(snapshot.binaryRules["newer"]?.ruleID, "newer-rule")
        // Wholesale replace: the baseline's rule is gone because the new doc's
        // rule list does not include it. Pinning this prevents a future bug
        // where apply() accidentally merges rather than replacing.
        XCTAssertNil(snapshot.binaryRules["baseline"], "newer doc must replace, not merge")
    }

    // MARK: apply: atomic in-memory swap to the newer snapshot

    // Applying version V then V+1 must leave the in-memory snapshot equal to V+1 immediately after acceptance, with the new
    // doc's rules replacing (not merging with) V's. Pins the "an incoming snapshot replaces the prior one atomically"
    // scenario: the lock.withLock swap in apply() is the atomic in-memory update; no exec can observe a half-applied state
    // because currentSnapshot() reads the whole struct under the same lock.
    // swiftlint:disable:next line_length
    func test_spec_extension_application_control_snapshot_is_the_source_of_truth_for_decisions_an_incoming_snapshot_replaces_the_prior_one_atomically() {
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 9, version: 1,
            rules: [RuleSpec(type: "BINARY", identifier: "v1-rule", ruleID: "r-v1")]
        ))
        XCTAssertEqual(store.currentSnapshot().policyVersion, 1)
        store.apply(rawJSON: document(
            policyID: 9, version: 2,
            rules: [RuleSpec(type: "BINARY", identifier: "v2-rule", ruleID: "r-v2")]
        ))
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyVersion, 2, "in-memory snapshot must be V+1 immediately after acceptance")
        XCTAssertEqual(snapshot.binaryRules["v2-rule"]?.ruleID, "r-v2")
        XCTAssertNil(snapshot.binaryRules["v1-rule"], "the swap replaces wholesale; the prior version's rules are gone")
    }

    // MARK: apply: first apply writes the typed file, replacing any prior on-disk file

    /// A legacy / pre-existing file at the storage path must be overwritten by the typed snapshot on first apply. The persist
    /// path uses Data.write(to:options:.atomic), which replaces the destination, so a fresh store loading the same path back
    /// sees the new typed document, not the legacy bytes. Pins "a first apply replaces any prior snapshot file".
    func test_spec_extension_application_control_snapshot_persistence_format_is_typed_a_first_apply_replaces_any_prior_snapshot_file() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppControlLegacy-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("application-control.json")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        // Seed a legacy / foreign file at the exact path the typed snapshot will be written to.
        try Data(#"{"legacy":"singleton-blocklist-format"}"#.utf8).write(to: url)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }

        let store = ApplicationControlStore(storagePath: url.path)
        store.apply(rawJSON: document(
            policyID: 3, version: 1,
            rules: [RuleSpec(type: "TEAMID", identifier: "FDG8Q7N4CC", ruleID: "r1")]
        ))
        // The legacy file already exists at the path, so a bare file-exists poll would return immediately against stale
        // bytes; poll until the async persist has actually overwritten the legacy content with the typed document.
        let deadline = Date().addingTimeInterval(2)
        var onDisk = try Data(contentsOf: url)
        while Date() < deadline, String(data: onDisk, encoding: .utf8)?.contains("singleton-blocklist-format") == true {
            Thread.sleep(forTimeInterval: 0.01)
            onDisk = (try? Data(contentsOf: url)) ?? onDisk
        }

        // The on-disk bytes are now the typed document; the legacy key is gone and the typed snapshot decodes.
        let asString = String(data: onDisk, encoding: .utf8) ?? ""
        XCTAssertFalse(asString.contains("singleton-blocklist-format"), "legacy file must be replaced, got: \(asString)")
        let decoded = try JSONDecoder().decode(ApplicationControlDocument.self, from: onDisk)
        XCTAssertEqual(decoded.policyID, 3)
        XCTAssertEqual(decoded.rules.first?.ruleType, "TEAMID")
    }

    // MARK: apply: deadline_fallback default substitution

    /// A snapshot payload that omits deadline_fallback must decode to the fail-closed posture (FallbackPosture.defaultPosture)
    /// so a deadline-exceeded BINARY consultation DENies by default. Pins "missing deadline_fallback substitutes fail-closed".
    /// The document() helper above never emits the field, so its output is exactly the omitted-field wire shape.
    func test_spec_extension_application_control_deadline_fallback_posture_missing_deadline_fallback_substitutes_fail_closed() {
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 1, version: 1,
            rules: [RuleSpec(type: "BINARY", identifier: "any-binary", ruleID: "r1")]
        ))
        XCTAssertEqual(store.currentSnapshot().deadlineFallback, .failClosed,
                       "omitted deadline_fallback must substitute the fail-closed default")
    }

    // MARK: apply: cross-policy regression accepted

    func testApplyAcceptsDifferentPolicyEvenAtLowerVersion() {
        // The monotonic gate is keyed on policyID -- a different policy can land at any version
        // because it is, by construction, a fresh policy stream. Pin this so a future
        // tightening of the gate (e.g. comparing version globally) doesn't accidentally start
        // rejecting legitimate policy swaps.
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 1, version: 100,
            rules: [RuleSpec(type: "BINARY", identifier: "old-policy-rule", ruleID: "old")]
        ))
        store.apply(rawJSON: document(
            policyID: 2, version: 1,
            rules: [RuleSpec(type: "BINARY", identifier: "new-policy-rule", ruleID: "new")]
        ))
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 2)
        XCTAssertEqual(snapshot.policyVersion, 1)
        XCTAssertEqual(snapshot.binaryRules["new-policy-rule"]?.ruleID, "new")
        XCTAssertNil(snapshot.binaryRules["old-policy-rule"])
    }

    // MARK: apply: malformed input

    func testApplyIgnoresMalformedJSON() {
        let store = makeStore()
        // Seed a real snapshot first; malformed input must NOT regress that state.
        store.apply(rawJSON: document(
            policyID: 1, version: 10,
            rules: [RuleSpec(type: "BINARY", identifier: "good", ruleID: "good-rule")]
        ))
        store.apply(rawJSON: Data("{not json}".utf8))
        store.apply(rawJSON: Data())
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 1)
        XCTAssertEqual(snapshot.policyVersion, 10)
        XCTAssertEqual(snapshot.binaryRules["good"]?.ruleID, "good-rule",
                       "malformed JSON must not regress previously-applied snapshot")
    }

    // MARK: apply: unknown rule_type

    func testApplySkipsUnknownRuleTypeButLandsKnownOnes() {
        // FRUITCAKE is not a defined rule_type. The store logs a warning and skips
        // that entry but accepts the rest of the document, so a server-side
        // tagging mistake on a single rule does not break the entire snapshot.
        let store = makeStore()
        store.apply(rawJSON: document(
            policyID: 1, version: 1,
            rules: [
                RuleSpec(type: "BINARY", identifier: "good-binary", ruleID: "good"),
                RuleSpec(type: "FRUITCAKE", identifier: "weird", ruleID: "weird")
            ]
        ))
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 1)
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

    // MARK: persist + loadFromDisk round-trip

    // swiftlint:disable:next line_length
    func test_spec_extension_application_control_snapshot_is_the_source_of_truth_for_decisions_extension_restart_restores_the_last_applied_snapshot() {
        // The injectable storagePath unlocks a real end-to-end test: apply on one store writes
        // the snapshot to disk; a fresh store with the same path can loadFromDisk and observe the
        // identical snapshot. Previously this was untestable because the persist target was a
        // production /var/db path no test could write to.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppControlPersist-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("application-control.json")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }

        let writer = ApplicationControlStore(storagePath: url.path)
        writer.apply(rawJSON: document(
            policyID: 42, version: 7,
            rules: [
                RuleSpec(type: "BINARY", identifier: "hash-hex", ruleID: "r1"),
                RuleSpec(type: "TEAMID", identifier: "FDG8Q7N4CC", ruleID: "r2")
            ]
        ))
        XCTAssertTrue(waitForFile(at: url.path), "apply() must persist to disk within deadline")

        // A fresh store reading the same path must see the same snapshot.
        let reader = ApplicationControlStore(storagePath: url.path)
        reader.loadFromDisk()
        let snapshot = reader.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 42)
        XCTAssertEqual(snapshot.policyVersion, 7)
        XCTAssertEqual(snapshot.binaryRules["hash-hex"]?.ruleID, "r1")
        XCTAssertEqual(snapshot.teamIDRules["FDG8Q7N4CC"]?.ruleID, "r2")
    }

    // MARK: loadFromDisk: cold start

    func testLoadFromDiskWithMissingFileLeavesSnapshotEmpty() {
        // Cold start path: no persisted file at the expected path. The store logs an info-level
        // "no persisted snapshot at startup" and falls back to the empty snapshot rather than
        // crashing. The agent will push the current snapshot on its next command poll.
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("does-not-exist-\(UUID().uuidString).json").path
        let store = ApplicationControlStore(storagePath: missing)
        store.loadFromDisk()
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 0)
        XCTAssertEqual(snapshot.policyVersion, 0)
        XCTAssertTrue(snapshot.binaryRules.isEmpty)
    }

    // MARK: loadFromDisk: corrupt file

    func testLoadFromDiskWithMalformedFileLeavesSnapshotEmpty() {
        // Corruption path: the persisted JSON is unparseable (truncated write, manual edit, etc).
        // The store fails open with the empty snapshot rather than crashing or carrying stale
        // bytes -- the agent will push a fresh snapshot on the next poll cycle.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppControlCorrupt-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("application-control.json")
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data("{not json}".utf8).write(to: url)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }
        let store = ApplicationControlStore(storagePath: url.path)
        store.loadFromDisk()
        let snapshot = store.currentSnapshot()
        XCTAssertEqual(snapshot.policyID, 0)
        XCTAssertEqual(snapshot.policyVersion, 0)
    }

    // MARK: empty snapshot constant

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
