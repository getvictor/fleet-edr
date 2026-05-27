// AuthExecDecider tests: exhaustively cover the (posture × hashOutcome × precedence) matrix
// that the decider walks. Pure-logic tests -- no ESF, no Darwin time calls. The decider is the
// only piece of AUTH_EXEC logic that the SwiftPM target can exercise (ESFSubscriber.swift is
// excluded because it imports EndpointSecurity), so coverage here pins the v0.1.0 close-out of
// #205 (platform-binary semantics deferred to ESFSubscriber wire) and #208 (BINARY sync hash
// fallback posture).

@testable import EDRExtensionLogic
import XCTest

// MARK: - Free-function helpers (shared across AuthExecDeciderTests + AuthExecDeciderPhaseBTests)
//
// Helpers live at file scope rather than inside the test class because the class body length is bounded by SwiftLint
// (type_body_length = 300). The shared helpers are tiny enough that file-scope makes them naturally usable by the second
// test class that covers CERTIFICATE + PATH precedence. Keeping them private here scopes the symbols to the test target.

/// makeRule builds a minimal ApplicationControlRule with the supplied ruleType / identifier / action / enforcement. Other
/// fields are set to representative defaults so tests focus on the precedence walk and verdict mapping rather than per-rule
/// decoration.
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

/// makeSnapshot builds an ApplicationControlSnapshot with the supplied rule maps and the requested fallback posture. Maps
/// not supplied default to empty so the precedence walk for missing layers correctly returns no match. certificateRules +
/// pathRules joined the parameter list when CERTIFICATE / PATH wired through to the decider (PR for #210).
private func makeSnapshot(
    deadlineFallback: FallbackPosture = .defaultPosture,
    cdhashRules: [String: ApplicationControlRule] = [:],
    binaryRules: [String: ApplicationControlRule] = [:],
    signingIDRules: [String: ApplicationControlRule] = [:],
    teamIDRules: [String: ApplicationControlRule] = [:],
    certificateRules: [String: ApplicationControlRule] = [:],
    pathRules: [String: ApplicationControlRule] = [:]
) -> ApplicationControlSnapshot {
    return ApplicationControlSnapshot(
        policyID: 1,
        policyVersion: 1,
        deadlineFallback: deadlineFallback,
        binaryRules: binaryRules,
        cdhashRules: cdhashRules,
        signingIDRules: signingIDRules,
        certificateRules: certificateRules,
        teamIDRules: teamIDRules,
        pathRules: pathRules
    )
}

/// makeTuple wraps AuthTuple's memberwise init with every field defaulted to nil so existing tests can supply just the
/// field they exercise. Each new test case sets only the fields its precedence row depends on; the rest stay nil so the
/// walker correctly skips those layers. The default-everything pattern keeps the test surface readable and stable across
/// future AuthTuple field additions.
private func makeTuple(
    cdhash: String? = nil,
    leafCertSHA256: String? = nil,
    signingIDPrefixed: String? = nil,
    teamID: String? = nil,
    canonicalPath: String? = nil
) -> AuthTuple {
    return AuthTuple(
        cdhash: cdhash,
        leafCertSHA256: leafCertSHA256,
        signingIDPrefixed: signingIDPrefixed,
        teamID: teamID,
        canonicalPath: canonicalPath
    )
}

final class AuthExecDeciderTests: XCTestCase {

    // MARK: - No match returns allow

    func testNoMatchOnEmptySnapshotReturnsAllow() {
        let tuple = makeTuple(cdhash: "c0", signingIDPrefixed: "ABC:org.test", teamID: "ABCDEFGHIJ")
        let decision = decideAuthExec(tuple: tuple, snapshot: makeSnapshot(), hashOutcome: .notNeeded)
        XCTAssertEqual(decision, .allow)
    }

    // MARK: - CDHASH precedence

    func testCDHashBlockRuleReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashvalue")
        let tuple = makeTuple(cdhash: "cdhashvalue", signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "cdhashvalue"))
    }

    func testCDHashTakesPrecedenceOverBinaryEvenOnDeadlineExceeded() {
        // CDHASH layer runs before the BINARY layer's hashOutcome is consulted. If CDHASH matches,
        // the deadlineExceeded path is never reached -- the deny precedes any fallback verdict.
        let cdhashRule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "cdhashvalue")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "shaRaceCondition")
        let tuple = makeTuple(cdhash: "cdhashvalue", signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": cdhashRule], binaryRules: ["shaRaceCondition": binaryRule]),
            hashOutcome: .deadlineExceeded
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
        let tuple = makeTuple(cdhash: "cdhashvalue", signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(cdhashRules: ["cdhashvalue": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .allow)
    }

    // MARK: - BINARY precedence (hash-driven)

    func testBinaryMatchOnComputedHashReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "shavalue")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(binaryRules: ["shavalue": rule]), hashOutcome: .computed("shavalue")
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "shavalue"))
    }

    func testBinaryNoMatchOnComputedHashFallsThroughToSigningID() {
        let signRule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(signingIDRules: ["ABC:org.bad": signRule]),
            hashOutcome: .computed("nonMatchingSha")
        )
        XCTAssertEqual(decision, .deny(rule: signRule, matchedIdentifier: "ABC:org.bad"))
    }

    func testNotNeededHashSkipsBinaryLayerAndWalksRest() {
        // When the snapshot has no BINARY rules, handleAuthExec passes .notNeeded so the precedence
        // walk skips BINARY entirely and continues to SIGNINGID / TEAMID rather than applying the
        // fallback posture. This is the common case in practice.
        let teamRule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: "ABCDEFGHIJ")
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(teamIDRules: ["ABCDEFGHIJ": teamRule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: teamRule, matchedIdentifier: "ABCDEFGHIJ"))
    }

    // MARK: - Deadline-exceeded posture matrix
    //
    // The posture only applies AFTER the precedence walk continues past an unavailable BINARY
    // layer (.deadlineExceeded / .readFailed) and SIGNINGID + TEAMID both fail to match. A
    // definitive lower-precedence DENY beats BINARY uncertainty.

    func testDeadlineExceededFailClosedNoLowerRuleDeniesWithUndecidedAudit() {
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(
            deadlineFallback: .failClosed,
            binaryRules: ["anyShaWeCantSee": binaryRule]
        )
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .deadlineExceeded)
        XCTAssertEqual(decision, .denyWithUndecidedAudit(reason: .deadline))
    }

    func testDeadlineExceededFailOpenNoLowerRuleAllowsSilently() {
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(
            deadlineFallback: .failOpen,
            binaryRules: ["anyShaWeCantSee": binaryRule]
        )
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .deadlineExceeded)
        XCTAssertEqual(decision, .allow)
    }

    func testDeadlineExceededAuditOnlyNoLowerRuleAllowsAndEmitsUndecidedAudit() {
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(
            deadlineFallback: .auditOnly,
            binaryRules: ["anyShaWeCantSee": binaryRule]
        )
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .deadlineExceeded)
        XCTAssertEqual(decision, .allowWithUndecidedAudit(reason: .deadline))
    }

    // MARK: - Lower-precedence rules dominate BINARY uncertainty (Gemini critical)

    // Gemini Code Assist flagged the prior behaviour as a security bypass: under fail-open or
    // audit-only postures, a hash timeout would short-circuit the walk and silently disable any
    // SIGNINGID / TEAMID block rules. The corrected semantic continues the walk and only applies
    // the posture when no later layer matches.

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

    // MARK: - Read-failed posture matrix

    func testReadFailedFailClosedNoLowerRuleDeniesWithUndecidedAudit() {
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(deadlineFallback: .failClosed, binaryRules: ["anyShaWeCantSee": binaryRule])
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .readFailed)
        XCTAssertEqual(decision, .denyWithUndecidedAudit(reason: .readFailed))
    }

    func testReadFailedAuditOnlyNoLowerRuleAllowsAndEmitsUndecidedAudit() {
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: nil)
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let snapshot = makeSnapshot(deadlineFallback: .auditOnly, binaryRules: ["anyShaWeCantSee": binaryRule])
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .readFailed)
        XCTAssertEqual(decision, .allowWithUndecidedAudit(reason: .readFailed))
    }

    // MARK: - SIGNINGID / TEAMID layers

    func testSigningIDBlockRuleReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: "ABC:org.bad", teamID: nil)
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(signingIDRules: ["ABC:org.bad": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "ABC:org.bad"))
    }

    func testTeamIDBlockRuleReturnsDeny() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let tuple = makeTuple(cdhash: nil, signingIDPrefixed: nil, teamID: "ABCDEFGHIJ")
        let decision = decideAuthExec(
            tuple: tuple, snapshot: makeSnapshot(teamIDRules: ["ABCDEFGHIJ": rule]), hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "ABCDEFGHIJ"))
    }

    func testPrecedenceCDHashBeatsSigningIDOnSimultaneousBlock() {
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
}

/// AuthExecDeciderPhaseBTests covers CERTIFICATE + PATH precedence (PR for #210). Split from AuthExecDeciderTests because
/// the combined class body would exceed SwiftLint's type_body_length cap; the helpers (makeRule / makeSnapshot / makeTuple)
/// are free functions at file scope so both test classes share them without duplication.
final class AuthExecDeciderPhaseBTests: XCTestCase {

    // MARK: - CERTIFICATE layer (PR for #210)

    /// CERTIFICATE rules match on the 64-char lowercase hex SHA-256 of the leaf X.509 signing certificate. Operators set
    /// these as the surgical level for compromised-Developer-ID response: revoking a leaf cert hash neutralises every
    /// binary signed under that cert without taking down the whole TeamID cohort. Layer sits between BINARY and SIGNINGID
    /// in the precedence ladder (Santa's order).
    func testCertificateBlockRuleReturnsDeny() {
        let rule = makeRule(
            ruleType: ApplicationControlRuleType.certificate,
            identifier: "leafhashvalue"
        )
        let tuple = makeTuple(leafCertSHA256: "leafhashvalue")
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(certificateRules: ["leafhashvalue": rule]),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "leafhashvalue"))
    }

    /// Precedence: a CERTIFICATE block must dominate a lower-precedence SIGNINGID block. Both layers populated;
    /// CERTIFICATE matches first and the SIGNINGID rule is never consulted.
    func testCertificateBeatsSigningIDOnSimultaneousBlock() {
        let certRule = makeRule(ruleType: ApplicationControlRuleType.certificate, identifier: "leafhashvalue")
        let signRule = makeRule(ruleType: ApplicationControlRuleType.signingID, identifier: "ABC:org.bad")
        let tuple = makeTuple(leafCertSHA256: "leafhashvalue", signingIDPrefixed: "ABC:org.bad")
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(
                signingIDRules: ["ABC:org.bad": signRule],
                certificateRules: ["leafhashvalue": certRule]
            ),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: certRule, matchedIdentifier: "leafhashvalue"))
    }

    /// A binary with no leaf cert (unsigned / ad-hoc) and no CERTIFICATE rule in the map must NOT match even if the map
    /// has entries for other certs. Sanity check that the optional-binding skips the layer cleanly.
    func testCertificateNoMatchWhenLeafIsNil() {
        let certRule = makeRule(ruleType: ApplicationControlRuleType.certificate, identifier: "otherleafhash")
        let tuple = makeTuple(leafCertSHA256: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(certificateRules: ["otherleafhash": certRule]),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .allow)
    }

    /// Under fail-open with .deadlineExceeded, the walk still continues through CERTIFICATE before the posture fires.
    /// A CERTIFICATE block must enforce regardless of the BINARY uncertainty -- same property the SIGNINGID / TEAMID
    /// rows already pin, extended to CERTIFICATE.
    func testDeadlineExceededFailOpenStillEnforcesCertificateBlock() {
        let certRule = makeRule(ruleType: ApplicationControlRuleType.certificate, identifier: "leafhashvalue")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let tuple = makeTuple(leafCertSHA256: "leafhashvalue")
        let snapshot = makeSnapshot(
            deadlineFallback: .failOpen,
            binaryRules: ["anyShaWeCantSee": binaryRule],
            certificateRules: ["leafhashvalue": certRule]
        )
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .deadlineExceeded)
        XCTAssertEqual(decision, .deny(rule: certRule, matchedIdentifier: "leafhashvalue"))
    }

    // MARK: - PATH layer (PR for #210)

    /// PATH rules match on the canonical absolute path of the exec target. Lowest-trust layer in the ladder by design --
    /// paths are the most operator-spoofable identifier. The test fixture uses an exact canonical form; the canonicaliser
    /// (canonicalizePath in AuthExecDecider) is tested separately.
    func testPathBlockRuleReturnsDeny() {
        let rule = makeRule(
            ruleType: ApplicationControlRuleType.path,
            identifier: "/Applications/Foo.app/Contents/MacOS/Foo"
        )
        let tuple = makeTuple(canonicalPath: "/Applications/Foo.app/Contents/MacOS/Foo")
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(pathRules: ["/Applications/Foo.app/Contents/MacOS/Foo": rule]),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: rule, matchedIdentifier: "/Applications/Foo.app/Contents/MacOS/Foo"))
    }

    /// PATH sits at the bottom of the precedence ladder. A TEAMID block on the same exec must fire first, never giving
    /// PATH a chance to match. This pins the "PATH is last" property.
    func testTeamIDBeatsPathOnSimultaneousBlock() {
        let teamRule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "ABCDEFGHIJ")
        let pathRule = makeRule(ruleType: ApplicationControlRuleType.path, identifier: "/Applications/Foo.app/Contents/MacOS/Foo")
        let tuple = makeTuple(teamID: "ABCDEFGHIJ", canonicalPath: "/Applications/Foo.app/Contents/MacOS/Foo")
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(
                teamIDRules: ["ABCDEFGHIJ": teamRule],
                pathRules: ["/Applications/Foo.app/Contents/MacOS/Foo": pathRule]
            ),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .deny(rule: teamRule, matchedIdentifier: "ABCDEFGHIJ"))
    }

    /// A nil canonicalPath (caller couldn't canonicalise the exec path) must skip the PATH layer cleanly without affecting
    /// any other layer. Models the "canonicalize returned nil" branch in ESFSubscriber.buildAuthTuple.
    func testPathNoMatchWhenCanonicalPathIsNil() {
        let pathRule = makeRule(ruleType: ApplicationControlRuleType.path, identifier: "/Applications/Foo.app/Contents/MacOS/Foo")
        let tuple = makeTuple(canonicalPath: nil)
        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: makeSnapshot(pathRules: ["/Applications/Foo.app/Contents/MacOS/Foo": pathRule]),
            hashOutcome: .notNeeded
        )
        XCTAssertEqual(decision, .allow)
    }

    /// Under .deadlineExceeded with fail-closed posture, a PATH block in the snapshot must still dominate the
    /// posture verdict -- the walk continues past unresolved BINARY through every lower layer including PATH before
    /// applying the fallback. Pins the "lower-precedence deny dominates BINARY uncertainty" property at the lowest layer.
    func testDeadlineExceededFailClosedStillEnforcesPathBlock() {
        let pathRule = makeRule(ruleType: ApplicationControlRuleType.path, identifier: "/Applications/Foo.app/Contents/MacOS/Foo")
        let binaryRule = makeRule(ruleType: ApplicationControlRuleType.binary, identifier: "anyShaWeCantSee")
        let tuple = makeTuple(canonicalPath: "/Applications/Foo.app/Contents/MacOS/Foo")
        let snapshot = makeSnapshot(
            deadlineFallback: .failClosed,
            binaryRules: ["anyShaWeCantSee": binaryRule],
            pathRules: ["/Applications/Foo.app/Contents/MacOS/Foo": pathRule]
        )
        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: .deadlineExceeded)
        XCTAssertEqual(decision, .deny(rule: pathRule, matchedIdentifier: "/Applications/Foo.app/Contents/MacOS/Foo"))
    }
}

// MARK: - canonicalizePath tests

/// canonicalizePathTests pin the Swift implementation against the same rules as the server-side
/// `server/rules/internal/appcontrol/CanonicalizePath`. A PATH rule created in the server is persisted in its canonical
/// form (e.g. `/tmp/foo` -> `/private/tmp/foo`); the extension MUST produce the identical canonical form on the AUTH callback
/// or the rule never matches. The fixture deliberately mirrors the Go test table so a future-self auditing parity can
/// diff the two files visually.
final class CanonicalizePathTests: XCTestCase {

    func testPlainPathUnchanged() {
        XCTAssertEqual(canonicalizePath("/usr/bin/ls"), "/usr/bin/ls")
    }

    func testTmpRewrittenToPrivate() {
        XCTAssertEqual(canonicalizePath("/tmp/foo"), "/private/tmp/foo")
    }

    func testVarRewrittenToPrivate() {
        XCTAssertEqual(canonicalizePath("/var/db/x"), "/private/var/db/x")
    }

    func testEtcRewrittenToPrivate() {
        XCTAssertEqual(canonicalizePath("/etc/sudoers"), "/private/etc/sudoers")
    }

    func testEtcBareRewrittenToPrivate() {
        XCTAssertEqual(canonicalizePath("/etc"), "/private/etc")
    }

    func testTmpPrefixNotRewrittenWhenNotBoundaryAligned() {
        // `/tmpfoo/bar` is NOT under `/tmp`; the rewrite must only fire on a path-component boundary.
        XCTAssertEqual(canonicalizePath("/tmpfoo/bar"), "/tmpfoo/bar")
    }

    func testRedundantSlashesCollapsed() {
        XCTAssertEqual(canonicalizePath("/usr//bin///ls"), "/usr/bin/ls")
    }

    func testTrailingSlashCollapsed() {
        XCTAssertEqual(canonicalizePath("/usr/bin/"), "/usr/bin")
    }

    func testEmptyRejected() {
        XCTAssertNil(canonicalizePath(""))
    }

    func testRelativeRejected() {
        XCTAssertNil(canonicalizePath("tmp/foo"))
    }

    func testDotDotSegmentRejected() {
        XCTAssertNil(canonicalizePath("/var/foo/../../etc/sudoers"))
    }

    func testDotDotFinalSegmentRejected() {
        XCTAssertNil(canonicalizePath("/usr/bin/.."))
    }
}
