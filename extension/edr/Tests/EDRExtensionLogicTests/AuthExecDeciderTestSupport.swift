// Shared test fixtures for the AuthExecDecider test suites. These free functions are referenced by
// AuthExecDeciderTests (no-match / CDHASH / BINARY / posture matrix), AuthExecDeciderPhaseBTests (CERTIFICATE / PATH),
// and AuthExecDeciderSigningTests (SIGNINGID / TEAMID). They live in their own file -- rather than file-private inside
// one suite -- so all three suites share a single definition without duplication and without making any one test file
// breach SwiftLint's file_length cap. Symbols are internal (target-scoped), which is the narrowest visibility that lets
// sibling test files in the EDRExtensionLogicTests target reach them.

@testable import EDRExtensionLogic

/// makeRule builds a minimal ApplicationControlRule with the supplied ruleType / identifier / action / enforcement. Other
/// fields are set to representative defaults so tests focus on the precedence walk and verdict mapping rather than per-rule
/// decoration.
func makeRule(
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
func makeSnapshot(
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
        policyEpoch: 0,
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
func makeTuple(
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
