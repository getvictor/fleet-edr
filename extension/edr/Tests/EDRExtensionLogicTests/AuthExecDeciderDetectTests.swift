// AuthExecDeciderDetectTests pins what a DETECT rule does to an AUTH_EXEC: it blocks nothing, is reported as a would-block match when
// the exec is allowed, and never changes the verdict the snapshot's PROTECT rules and fallback posture reach on their own.

@testable import EDRExtensionLogic
import XCTest

final class AuthExecDeciderDetectTests: XCTestCase {

    // spec:extension-application-control/detect-mode-rules-report-would-block-matches/a-detect-rule-allows-and-reports-the-exec
    func testDetectRuleAllowsTheExecAndReportsTheMatch() {
        let rule = makeRule(
            ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashvalue", enforcement: ApplicationControlEnforcement.detect
        )
        let result = evaluateAuthExec(
            tuple: makeTuple(cdhash: "cdhashvalue"), snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(result, AuthEvaluation(decision: .allow, wouldBlock: RuleMatch(rule: rule, matchedIdentifier: "cdhashvalue")))
    }

    // spec:extension-application-control/detect-mode-rules-report-would-block-matches/a-would-block-match-names-the-matched-identifier
    func testWouldBlockMatchNamesTheRuleTypeAndMatchedIdentifier() {
        let rule = makeRule(
            ruleType: ApplicationControlRuleType.teamID, identifier: "EQHXZ8M8AV", enforcement: ApplicationControlEnforcement.detect
        )
        let result = evaluateAuthExec(
            tuple: makeTuple(signingIDPrefixed: "EQHXZ8M8AV:com.example.tool", teamID: "EQHXZ8M8AV"),
            snapshot: makeSnapshot(teamIDRules: ["EQHXZ8M8AV": rule]),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(result.decision, .allow)
        XCTAssertEqual(result.wouldBlock?.rule.ruleType, ApplicationControlRuleType.teamID)
        XCTAssertEqual(result.wouldBlock?.matchedIdentifier, "EQHXZ8M8AV")
    }

    // spec:extension-application-control/detect-mode-rules-report-would-block-matches/a-detect-rule-does-not-weaken-a-protect-rule
    func testDetectRuleAboveAProtectRuleLeavesTheExecDenied() {
        let detectRule = makeRule(
            ruleType: ApplicationControlRuleType.binary, identifier: "shavalue", enforcement: ApplicationControlEnforcement.detect
        )
        let protectRule = makeRule(ruleType: ApplicationControlRuleType.path, identifier: "/usr/local/bin/tool")
        let result = evaluateAuthExec(
            tuple: makeTuple(canonicalPath: "/usr/local/bin/tool"),
            snapshot: makeSnapshot(binaryRules: ["shavalue": detectRule], pathRules: ["/usr/local/bin/tool": protectRule]),
            hashOutcome: .computed("shavalue")
        )
        XCTAssertEqual(
            result,
            AuthEvaluation(decision: .deny(rule: protectRule, matchedIdentifier: "/usr/local/bin/tool"), wouldBlock: nil),
            "a lower-precedence PROTECT rule still denies, and a denied exec reports no would-block match"
        )
    }

    func testProtectRuleAboveADetectRuleDeniesWithoutReportingIt() {
        let protectRule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashvalue")
        let detectRule = makeRule(
            ruleType: ApplicationControlRuleType.teamID, identifier: "EQHXZ8M8AV", enforcement: ApplicationControlEnforcement.detect
        )
        let result = evaluateAuthExec(
            tuple: makeTuple(cdhash: "cdhashvalue", teamID: "EQHXZ8M8AV"),
            snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": protectRule], teamIDRules: ["EQHXZ8M8AV": detectRule]),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(result, AuthEvaluation(decision: .deny(rule: protectRule, matchedIdentifier: "cdhashvalue"), wouldBlock: nil))
    }

    // spec:extension-application-control/detect-mode-rules-report-would-block-matches/the-highest-precedence-detect-match-is-reported
    func testHighestPrecedenceDetectMatchIsReported() {
        let signingRule = makeRule(
            ruleType: ApplicationControlRuleType.signingID,
            identifier: "EQHXZ8M8AV:com.example.tool",
            enforcement: ApplicationControlEnforcement.detect
        )
        let teamRule = makeRule(
            ruleType: ApplicationControlRuleType.teamID, identifier: "EQHXZ8M8AV", enforcement: ApplicationControlEnforcement.detect
        )
        let result = evaluateAuthExec(
            tuple: makeTuple(signingIDPrefixed: "EQHXZ8M8AV:com.example.tool", teamID: "EQHXZ8M8AV"),
            snapshot: makeSnapshot(
                signingIDRules: ["EQHXZ8M8AV:com.example.tool": signingRule], teamIDRules: ["EQHXZ8M8AV": teamRule]
            ),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(result.wouldBlock, RuleMatch(rule: signingRule, matchedIdentifier: "EQHXZ8M8AV:com.example.tool"))
    }

    // spec:extension-application-control/detect-mode-rules-report-would-block-matches/a-detect-only-binary-rule-never-fails-closed
    func testDetectOnlyBinaryRuleNeverAppliesThePosture() {
        let binaryRule = makeRule(
            ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee", enforcement: ApplicationControlEnforcement.detect
        )
        for hashOutcome in [HashOutcome.deadlineExceeded, .readFailed] {
            let result = evaluateAuthExec(
                tuple: makeTuple(),
                snapshot: makeSnapshot(deadlineFallback: .failClosed, binaryRules: ["anyShaWeCantSee": binaryRule]),
                hashOutcome: hashOutcome
            )
            XCTAssertEqual(result, AuthEvaluation(decision: .allow, wouldBlock: nil), "hash outcome \(hashOutcome)")
        }
    }

    // spec:extension-application-control/detect-mode-rules-report-would-block-matches/the-fallback-posture-still-applies
    func testDetectMatchLeavesTheFallbackPostureInForce() {
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let teamRule = makeRule(
            ruleType: ApplicationControlRuleType.teamID, identifier: "EQHXZ8M8AV", enforcement: ApplicationControlEnforcement.detect
        )
        let match = RuleMatch(rule: teamRule, matchedIdentifier: "EQHXZ8M8AV")
        let cases: [(posture: FallbackPosture, want: AuthEvaluation)] = [
            (.failClosed, AuthEvaluation(decision: .denyWithUndecidedAudit(reason: .deadline), wouldBlock: nil)),
            (.failOpen, AuthEvaluation(decision: .allow, wouldBlock: match)),
            (.auditOnly, AuthEvaluation(decision: .allowWithUndecidedAudit(reason: .deadline), wouldBlock: match))
        ]
        for testCase in cases {
            let snapshot = makeSnapshot(
                deadlineFallback: testCase.posture,
                binaryRules: ["anyShaWeCantSee": binaryRule],
                teamIDRules: ["EQHXZ8M8AV": teamRule]
            )
            let result = evaluateAuthExec(tuple: makeTuple(teamID: "EQHXZ8M8AV"), snapshot: snapshot, hashOutcome: .deadlineExceeded)
            XCTAssertEqual(result, testCase.want, "posture \(testCase.posture)")
        }
    }

    // MARK: Exhaustive invariant

    private enum LayerState: CaseIterable {
        case absent, protect, detect
    }

    private static let layerTypes = [
        ApplicationControlRuleType.cdhash,
        ApplicationControlRuleType.binary,
        ApplicationControlRuleType.certificate,
        ApplicationControlRuleType.signingID,
        ApplicationControlRuleType.teamID,
        ApplicationControlRuleType.path
    ]

    private static let fullTuple = makeTuple(
        cdhash: "cdhashvalue",
        leafCertSHA256: "leafcertvalue",
        signingIDPrefixed: "EQHXZ8M8AV:com.example.tool",
        teamID: "EQHXZ8M8AV",
        canonicalPath: "/usr/local/bin/tool"
    )

    private static let identifiers = ["cdhashvalue", "shavalue", "leafcertvalue", "EQHXZ8M8AV:com.example.tool", "EQHXZ8M8AV",
                                      "/usr/local/bin/tool"]

    private func snapshot(states: [LayerState], posture: FallbackPosture, keepDetect: Bool) -> ApplicationControlSnapshot {
        var maps = [[String: ApplicationControlRule]](repeating: [:], count: states.count)
        for (layer, state) in states.enumerated() {
            let identifier = Self.identifiers[layer]
            switch state {
            case .absent:
                continue
            case .protect:
                maps[layer][identifier] = makeRule(ruleType: Self.layerTypes[layer], identifier: identifier)
            case .detect where keepDetect:
                maps[layer][identifier] = makeRule(
                    ruleType: Self.layerTypes[layer], identifier: identifier, enforcement: ApplicationControlEnforcement.detect
                )
            case .detect:
                continue
            }
        }
        return makeSnapshot(
            deadlineFallback: posture,
            cdhashRules: maps[0],
            binaryRules: maps[1],
            signingIDRules: maps[3],
            teamIDRules: maps[4],
            certificateRules: maps[2],
            pathRules: maps[5]
        )
    }

    // Every combination of no rule, a PROTECT rule, or a DETECT rule on each of the six layers, under every hash outcome and
    // posture. The BINARY layer can only match when the hash was computed, so it is the one layer whose matchability varies.
    //
    // spec:extension-application-control/detect-mode-rules-report-would-block-matches/a-detect-rule-does-not-weaken-a-protect-rule
    func testDetectRulesNeverChangeTheVerdictAndTheFirstMatchableOneIsReported() {
        let hashOutcomes: [HashOutcome] = [.computed("shavalue"), .deadlineExceeded, .readFailed, .notNeeded]
        let layerCount = Self.layerTypes.count
        let stateCount = LayerState.allCases.count
        var combinations = 0
        for code in 0..<Int(pow(Double(stateCount), Double(layerCount))) {
            var remainder = code
            var states: [LayerState] = []
            for _ in 0..<layerCount {
                states.append(LayerState.allCases[remainder % stateCount])
                remainder /= stateCount
            }
            for hashOutcome in hashOutcomes {
                for posture in [FallbackPosture.failClosed, .failOpen, .auditOnly] {
                    combinations += 1
                    let withDetect = evaluateAuthExec(
                        tuple: Self.fullTuple, snapshot: snapshot(states: states, posture: posture, keepDetect: true), hashOutcome: hashOutcome
                    )
                    // The wire side hashes only when the snapshot has BINARY rules, so the snapshot without its DETECT rules gets the
                    // outcome it would have been given, not the one the DETECT rules made possible.
                    let stripped = snapshot(states: states, posture: posture, keepDetect: false)
                    let withoutDetect = evaluateAuthExec(
                        tuple: Self.fullTuple, snapshot: stripped, hashOutcome: stripped.binaryRules.isEmpty ? .notNeeded : hashOutcome
                    )
                    let label = "states \(states) hash \(hashOutcome) posture \(posture)"
                    XCTAssertEqual(withDetect.decision, withoutDetect.decision, label)
                    XCTAssertNil(withoutDetect.wouldBlock, label)

                    let hashComputed = hashOutcome == .computed("shavalue")
                    let firstDetect = states.indices.first { layer in
                        states[layer] == .detect && (layer != 1 || hashComputed)
                    }
                    let allows: Bool
                    switch withDetect.decision {
                    case .allow, .allowWithUndecidedAudit:
                        allows = true
                    case .deny, .denyWithUndecidedAudit:
                        allows = false
                    }
                    let want = firstDetect.flatMap { layer in allows ? Self.identifiers[layer] : nil }
                    XCTAssertEqual(withDetect.wouldBlock?.matchedIdentifier, want, label)
                    XCTAssertEqual(withDetect.wouldBlock?.rule.enforcement ?? ApplicationControlEnforcement.detect,
                                   ApplicationControlEnforcement.detect, label)
                }
            }
        }
        XCTAssertEqual(combinations, 8748)
    }
}
