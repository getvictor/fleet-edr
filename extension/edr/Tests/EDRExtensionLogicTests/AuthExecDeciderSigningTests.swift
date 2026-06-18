// AuthExecDeciderSigningTests covers the SIGNINGID + TEAMID precedence layers of decideAuthExec, plus the
// "a definitive lower-precedence DENY dominates BINARY uncertainty" property for those two layers. Split out of
// AuthExecDeciderTests so that file stays under SwiftLint's file_length cap (500). The shared helpers
// (makeRule / makeSnapshot / makeTuple) live at file scope in AuthExecDeciderTests.swift and are internal to the
// EDRExtensionLogicTests target, so this sibling file uses them directly without redefining them.
//
// The marker function names carry the canonical spec scenario id verbatim (slashes and dashes mapped to
// underscores), which spectrace matches as the coverage marker. Those names are unavoidably longer than the
// 150-char cap, so each carries a targeted single-line, single-rule line-length exception scoped to exactly the one
// declaration line that cannot be wrapped (a Swift function name has no legal line break), never a blanket file disable.

@testable import EDRExtensionLogic
import XCTest

final class AuthExecDeciderSigningTests: XCTestCase {

    // MARK: SIGNINGID / TEAMID layers

    // A SIGNINGID rule keyed on a `<team_id>:<signing_id>` identifier matches a signed non-Apple binary whose tuple carries
    // that same prefixed signing identity. The deny verdict (and the matched identifier echoed in the block event) is the
    // observable proof that buildAuthTuple assembled the `<team_id>:<signing_id>` shape from a signed third-party target;
    // the tuple struct's internal contents are not externally observable, but a SIGNINGID match on the prefixed value is.
    // swiftlint:disable:next line_length
    func test_spec_extension_application_control_target_identifier_tuple_for_every_exec_a_signing_id_rule_matches_a_signed_non_apple_binary_by_its_prefixed_signing_identity() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(signingIDRules: ["ABC:org.bad": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "ABC:org.bad"))
    }

    // A SIGNINGID rule keyed on a `platform:<signing_id>` identifier matches a kernel-classified Apple platform binary whose
    // tuple carries that platform-prefixed signing identity. Pins the observable consequence of buildAuthTuple's
    // `platform:<signing_id>` shaping (the platform prefix is otherwise an internal tuple detail): a SIGNINGID rule on the
    // platform-prefixed value denies and the matched identifier is the platform-prefixed string. (At AUTH time the
    // platform-binary carve-out short-circuits before the walk; this L0 test exercises the decider's matching of the
    // platform-prefixed signing identity directly, which the carve-out does not gate.)
    // swiftlint:disable:next line_length
    func test_spec_extension_application_control_target_identifier_tuple_for_every_exec_a_signing_id_rule_matches_a_platform_binary_by_its_platform_prefixed_signing_identity() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "platform:com.apple.curl")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: "platform:com.apple.curl", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(signingIDRules: ["platform:com.apple.curl": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "platform:com.apple.curl"))
    }

    func test_spec_extension_application_control_block_event_emission_a_block_emits_a_block_event_whose_matched_identifier_matches_the_rule_type() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: "ABCDEFGHIJ")
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(teamIDRules: ["ABCDEFGHIJ": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "ABCDEFGHIJ"))
    }

    func test_spec_extension_application_control_precedence_walk_a_more_specific_match_wins_over_a_less_specific_one() {
        // Both CDHASH and SIGNINGID layers have block rules; the precedence walk must return
        // the CDHASH match (higher priority) and never consult SIGNINGID.
        let cdRule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashfirst")
        let signRule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = makeTuple(cdhash: "cdhashfirst", signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(cdhashRules: ["cdhashfirst": cdRule], signingIDRules: ["ABC:org.bad": signRule]),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: cdRule, matchedIdentifier: "cdhashfirst"))
    }

    // MARK: Lower-precedence rules dominate BINARY uncertainty (Gemini critical)
    //
    // Gemini Code Assist flagged the prior behaviour as a security bypass: under fail-open or audit-only postures, a hash
    // timeout would short-circuit the walk and silently disable any SIGNINGID / TEAMID block rules. The corrected semantic
    // continues the walk and only applies the posture when no later layer matches.

    func testDeadlineExceededFailOpenStillEnforcesSigningIDBlock() {
        let signRule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let snapshot = makeSnapshot(
            deadlineFallback: .failOpen,
            binaryRules: ["anyShaWeCantSee": binaryRule],
            signingIDRules: ["ABC:org.bad": signRule]
        )
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .deadlineExceeded)
        XCTAssertEqual(decision, .deny(rule: signRule, matchedIdentifier: "ABC:org.bad"))
    }

    func testReadFailedAuditOnlyStillEnforcesTeamIDBlock() {
        let teamRule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: "ABCDEFGHIJ")
        let snapshot = makeSnapshot(
            deadlineFallback: .auditOnly,
            binaryRules: ["anyShaWeCantSee": binaryRule],
            teamIDRules: ["ABCDEFGHIJ": teamRule]
        )
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .readFailed)
        XCTAssertEqual(decision, .deny(rule: teamRule, matchedIdentifier: "ABCDEFGHIJ"))
    }
}
