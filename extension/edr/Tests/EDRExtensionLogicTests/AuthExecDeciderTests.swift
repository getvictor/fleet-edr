// AuthExecDecider tests: exhaustively cover the (posture × hashOutcome × precedence) matrix
// that the decider walks. Pure-logic tests -- no ESF, no Darwin time calls. The decider is the
// only piece of AUTH_EXEC logic that the SwiftPM target can exercise (ESFSubscriber.swift is
// excluded because it imports EndpointSecurity), so coverage here pins the v0.1.0 close-out of
// #205 (platform-binary semantics deferred to ESFSubscriber wire) and #208 (BINARY sync hash
// fallback posture).

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class AuthExecDeciderTests: XCTestCase {

    // MARK: - Helpers

    /// makeRule builds a minimal ApplicationControlRule with the supplied ruleType / identifier /
    /// action / enforcement. Other fields are set to representative defaults so the tests focus
    /// on the precedence walk and verdict mapping rather than per-rule decoration.
    private func makeRule(
        ruleType: String,
        identifier: String,
        action: String = ApplicationControlAction.block,
        enforcement: String = ApplicationControlEnforcement.protect
    ) -> ApplicationControlRule {
        return ApplicationControlRule(
            ruleID: "app_control:test-\(identifier)",
            ruleType: ruleType,
            identifier: identifier,
            action: action,
            enforcement: enforcement,
            severity: "medium",
            customMsg: nil,
            customURL: nil
        )
    }

    /// makeSnapshot builds an ApplicationControlSnapshot with the supplied rule maps and the
    /// requested fallback posture. Maps not supplied default to empty so the precedence walk
    /// for missing layers correctly returns no match.
    private func makeSnapshot(
        deadlineFallback: FallbackPosture = .defaultPosture,
        cdhashRules: [String: ApplicationControlRule] = [:],
        binaryRules: [String: ApplicationControlRule] = [:],
        signingIDRules: [String: ApplicationControlRule] = [:],
        teamIDRules: [String: ApplicationControlRule] = [:]
    ) -> ApplicationControlSnapshot {
        return ApplicationControlSnapshot(
            policyID: 1,
            policyVersion: 1,
            deadlineFallback: deadlineFallback,
            binaryRules: binaryRules,
            cdhashRules: cdhashRules,
            signingIDRules: signingIDRules,
            certificateRules: [:],
            teamIDRules: teamIDRules,
            pathRules: [:]
        )
    }

    // MARK: - No match returns allow

    func testNoMatchOnEmptySnapshotReturnsAllow() {
        let tuple = AuthTuple(cdhash: "c0", signingIDPrefixed: "ABC:org.test", teamID: "ABCDEFGHIJ")
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(),
            hashOutcome: .notNeeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .allow)
    }

    // MARK: - CDHASH precedence

    func testCDHashBlockRuleReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashvalue")
        let tuple = AuthTuple(cdhash: "cdhashvalue", signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": rule]),
            hashOutcome: .notNeeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "cdhashvalue"))
    }

    func testCDHashTakesPrecedenceOverBinaryEvenOnDeadlineExceeded() {
        // CDHASH layer runs before the BINARY layer's hashOutcome is consulted. If CDHASH matches,
        // the deadlineExceeded path is never reached -- the deny precedes any fallback verdict.
        let cdhashRule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashvalue")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "shaRaceCondition")
        let tuple = AuthTuple(cdhash: "cdhashvalue", signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": cdhashRule], binaryRules: ["shaRaceCondition": binaryRule]),
            hashOutcome: .deadlineExceeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: cdhashRule, matchedIdentifier: "cdhashvalue"))
    }

    func testCDHashNonProtectEnforcementAllows() {
        // DETECT enforcement is the v0.1.x lift-and-detect mode; it must NOT deny in v0.1.0.
        let rule = makeRule(
            ruleType: ApplicationControlRuleType.cdhash,
            identifier: "cdhashvalue",
            enforcement: ApplicationControlEnforcement.detect
        )
        let tuple = AuthTuple(cdhash: "cdhashvalue", signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": rule]),
            hashOutcome: .notNeeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .allow)
    }

    // MARK: - BINARY precedence (hash-driven)

    func testBinaryMatchOnComputedHashReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "shavalue")
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(binaryRules: ["shavalue": rule]),
            hashOutcome: .computed("shavalue"),
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "shavalue"))
    }

    func testBinaryNoMatchOnComputedHashFallsThroughToSigningID() {
        let signRule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(signingIDRules: ["ABC:org.bad": signRule]),
            hashOutcome: .computed("nonMatchingSha"),
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: signRule, matchedIdentifier: "ABC:org.bad"))
    }

    func testNotNeededHashSkipsBinaryLayerAndWalksRest() {
        // When the snapshot has no BINARY rules, handleAuthExec passes .notNeeded so the precedence
        // walk skips BINARY entirely and continues to SIGNINGID / TEAMID rather than applying the
        // fallback posture. This is the common case in practice.
        let teamRule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: nil, teamID: "ABCDEFGHIJ")
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(teamIDRules: ["ABCDEFGHIJ": teamRule]),
            hashOutcome: .notNeeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: teamRule, matchedIdentifier: "ABCDEFGHIJ"))
    }

    // MARK: - Deadline-exceeded posture matrix

    func testDeadlineExceededFailClosedDeniesWithUndecidedAudit() {
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: "ABC:org.test", teamID: "ABCDEFGHIJ")
        // SIGNINGID + TEAMID rules exist; under failClosed the deadline-exceeded path is the
        // verdict and the later layers are NOT consulted. Tests guarantee BINARY uncertainty
        // dominates any post-BINARY precedence match.
        let signRule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.test")
        let teamRule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(
            deadlineFallback: .failClosed,
            binaryRules: ["anyShaWeCantSee": binaryRule],
            signingIDRules: ["ABC:org.test": signRule],
            teamIDRules: ["ABCDEFGHIJ": teamRule]
        )
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: snapshot,
            hashOutcome: .deadlineExceeded,
            posture: snapshot.deadlineFallback
        )
        XCTAssertEqual(decision, .denyWithUndecidedAudit(reason: .deadline))
    }

    func testDeadlineExceededFailOpenAllowsSilently() {
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: "ABC:org.test", teamID: "ABCDEFGHIJ")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(
            deadlineFallback: .failOpen,
            binaryRules: ["anyShaWeCantSee": binaryRule]
        )
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: snapshot,
            hashOutcome: .deadlineExceeded,
            posture: snapshot.deadlineFallback
        )
        XCTAssertEqual(decision, .allow)
    }

    func testDeadlineExceededAuditOnlyAllowsAndEmitsUndecidedAudit() {
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(
            deadlineFallback: .auditOnly,
            binaryRules: ["anyShaWeCantSee": binaryRule]
        )
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: snapshot,
            hashOutcome: .deadlineExceeded,
            posture: snapshot.deadlineFallback
        )
        XCTAssertEqual(decision, .allowWithUndecidedAudit(reason: .deadline))
    }

    // MARK: - Read-failed posture matrix

    func testReadFailedFailClosedDeniesWithUndecidedAudit() {
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(deadlineFallback: .failClosed, binaryRules: ["anyShaWeCantSee": binaryRule])
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: snapshot,
            hashOutcome: .readFailed,
            posture: snapshot.deadlineFallback
        )
        XCTAssertEqual(decision, .denyWithUndecidedAudit(reason: .readFailed))
    }

    func testReadFailedAuditOnlyAllowsAndEmitsUndecidedAudit() {
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(deadlineFallback: .auditOnly, binaryRules: ["anyShaWeCantSee": binaryRule])
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: snapshot,
            hashOutcome: .readFailed,
            posture: snapshot.deadlineFallback
        )
        XCTAssertEqual(decision, .allowWithUndecidedAudit(reason: .readFailed))
    }

    // MARK: - SIGNINGID / TEAMID layers

    func testSigningIDBlockRuleReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(signingIDRules: ["ABC:org.bad": rule]),
            hashOutcome: .notNeeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "ABC:org.bad"))
    }

    func testTeamIDBlockRuleReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let tuple = AuthTuple(cdhash: nil, signingIDPrefixed: nil, teamID: "ABCDEFGHIJ")
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(teamIDRules: ["ABCDEFGHIJ": rule]),
            hashOutcome: .notNeeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "ABCDEFGHIJ"))
    }

    func testPrecedenceCDHashBeatsSigningIDOnSimultaneousBlock() {
        // Both CDHASH and SIGNINGID layers have block rules; the precedence walk must return
        // the CDHASH match (higher priority) and never consult SIGNINGID.
        let cdRule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashfirst")
        let signRule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = AuthTuple(cdhash: "cdhashfirst", signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(cdhashRules: ["cdhashfirst": cdRule], signingIDRules: ["ABC:org.bad": signRule]),
            hashOutcome: .notNeeded,
            posture: .failClosed
        )
        XCTAssertEqual(decision, .deny(rule: cdRule, matchedIdentifier: "cdhashfirst"))
    }
}
