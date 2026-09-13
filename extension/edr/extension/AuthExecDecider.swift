import os

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "AuthExecDecider")

/// FallbackPosture is the operator-selectable verdict when sync hashing for a BINARY rule consultation cannot complete within the
/// AUTH_EXEC kernel deadline budget. The three options trade enforcement strictness against exec-startup latency:
///   - failClosed: DENY the exec. The high-assurance posture; a binary the EDR cannot identify in time does not run. Default for
///     new pilots because it is the only posture that closes the cold-cache first-exec window without operator awareness of the
///     trade-off. Emits an application_control_undecided event with verdict=deny so the operator can audit how often the
///     fallback fires.
///   - failOpen: ALLOW the exec. The demo-equivalent posture; the cold-cache window stays open. Operators who pick this are
///     prioritising "no unexpected blocks" over "no first-exec bypass." No audit event (the operator opted out of visibility).
///   - auditOnly: ALLOW the exec and emit application_control_undecided with verdict=allow so the operator can count how often
///     the deadline window misses without changing exec behaviour. The right posture for an operator tuning their fleet's
///     fallback before flipping to failClosed.
/// Stable across the wire; renaming any case is a contract break with server/rules/api.FallbackPosture.
enum FallbackPosture: String, Codable, Sendable {
    case failClosed = "fail-closed"
    case failOpen = "fail-open"
    case auditOnly = "audit-only"

    /// defaultPosture is the value applied when the snapshot payload omits the deadline_fallback field. failClosed because v0.1.0
    /// is the first real release (not a demo), and a binary the EDR cannot identify within the kernel deadline window is, by
    /// construction, an unknown. An unknown should not run on a fleet whose operator has chosen to enable Application Control.
    static let defaultPosture: FallbackPosture = .failClosed
}

/// HashOutcome carries the result of the AUTH_EXEC sync SHA-256 attempt to the decision walker. The decider does NOT compute the
/// hash itself: FileHashCache.computeSHA256WithDeadline lives on the wire side because it touches Darwin (mach_absolute_time) and
/// the on-disk handle. The decider is pure: it consumes the outcome and returns a decision.
enum HashOutcome: Equatable, Sendable {
    /// Hex SHA-256 is available (cache hit, or sync compute completed within budget). Drives the BINARY map lookup.
    case computed(String)
    /// Sync compute could not complete within the deadline budget (large binary, slow disk). Decider applies the posture.
    case deadlineExceeded
    /// File could not be opened, fstat failed, or the TOCTOU re-check found a different (dev,inode,mtime) tuple between AUTH
    /// and read. Distinct from deadlineExceeded so audit events carry the right reason; the decider treats both as unavailable.
    case readFailed
    /// Skipped entirely because the active snapshot has no BINARY rules. Avoids charging the AUTH callback for a hash compute
    /// whose result no rule would consult. Walked past without applying the fallback posture.
    case notNeeded
}

/// UndecidedReason is the operator-facing tag carried on application_control_undecided events. Stable across the wire so
/// dashboards can group on the value. Subset of HashOutcome's unavailable cases (notNeeded never produces an undecided event,
/// computed always carries a real decision).
enum UndecidedReason: String, Sendable {
    case deadline
    case readFailed = "read_failed"
}

/// AuthTuple captures the identifier values the decision walker compares against the snapshot's per-type maps. Each field is
/// optional: absent values mean "the target has no value of this kind", and the precedence walker skips that map. Sendable so
/// callers can build the tuple on the AUTH callback thread and hand it to a future async pipeline without bridging tricks.
///
/// PR for #210 closed out Phase B by adding leafCertSHA256 + canonicalPath; the snapshot maps for both rule types
/// (certificateRules, pathRules) were already populated by ApplicationControlStore.makeSnapshot. The decision walker now
/// honours every wire-enum rule type.
struct AuthTuple: Equatable, Sendable {
    /// 40-char lowercase hex CDHash, only when the target runs under Apple's Hardened Runtime (CS_RUNTIME); see the comment on
    /// isHardenedRuntime in CDHashHex.swift for the lazy-page-mapping rationale.
    let cdhash: String?
    /// 64-char lowercase hex SHA-256 of the leaf X.509 signing cert. nil when the binary is unsigned, ad-hoc-signed, or
    /// SecCode can't read the on-disk binary. Populated by SigningInfoFallback.leafCertSHA256 once per (inode, mtime).
    let leafCertSHA256: String?
    /// "<TeamID>:<bundle.id>" for third-party signed binaries, "platform:<bundle.id>" for kernel-classified Apple platform
    /// binaries. nil when ESF reports neither a usable team_id (real or fallback) nor a platform classification.
    let signingIDPrefixed: String?
    /// 10-char Apple Developer Team ID. nil when ESF redacts team_id (ad-hoc-signed extension on edr-dev) and
    /// SigningInfoFallback also cannot recover a real value.
    let teamID: String?
    /// Canonical absolute path of the exec target (filepath.Clean equivalent), with /tmp + /var + /etc rewritten to /private.
    /// nil when the wire path is empty, relative, or contains a `..` segment (defensive; ESF reports an absolute path under
    /// normal conditions). PATH rules compare against this verbatim, so the canonicalisation MUST match the server-side
    /// CanonicalizePath rules exactly or rules created against the operator's canonical form will never match.
    let canonicalPath: String?
}

/// AuthDecision is the discrete verdict the wire side dispatches on. Cases enumerate every action handleAuthExec can take short
/// of the kernel-cached platform-binary carve-out and the unconditional self-allow failsafe (both short-circuit before the
/// decider runs).
enum AuthDecision: Equatable, Sendable {
    /// Allow the exec; the result IS pinned into the kernel AUTH cache (see authResultIsCacheable) unless a DETECT rule
    /// matched. Used when no PROTECT rule matched and the hash either was not needed (no BINARY rules) or returned a clean
    /// miss against the BINARY map. The verdict is a
    /// pure function of the stable identity tuple and the active snapshot, and ApplicationControlStore flushes the kernel
    /// cache (es_clear_cache) on every snapshot swap, so a later rule update still takes effect on the next exec (#209).
    case allow
    /// Allow the exec and emit an application_control_undecided event with verdict=allow and the given reason. Fires only
    /// under auditOnly posture when the hash is unavailable.
    case allowWithUndecidedAudit(reason: UndecidedReason)
    /// Deny the exec; emit application_control_block + block notification with the matched rule + identifier.
    case deny(rule: ApplicationControlRule, matchedIdentifier: String)
    /// Deny the exec and emit application_control_undecided with verdict=deny. Fires only under failClosed posture when the
    /// hash is unavailable. Separate from .deny because there is no actual matched rule, only the posture's verdict.
    case denyWithUndecidedAudit(reason: UndecidedReason)
}

/// RuleMatch is a snapshot rule together with the value from the exec's identity tuple that matched it: the CDHash that hit a
/// CDHASH rule, the team id that hit a TEAMID rule, and so on.
struct RuleMatch: Equatable, Sendable {
    let rule: ApplicationControlRule
    let matchedIdentifier: String
}

/// AuthEvaluation is the decider's whole answer for one AUTH_EXEC: the verdict the kernel receives, and the DETECT rule the
/// exec matched, which the wire side reports as an application_control_would_block event. wouldBlock is set only when the
/// verdict allows the exec. A DETECT rule records what enforcing it would have done, and an exec that is denied anyway has
/// nothing of that kind to report.
struct AuthEvaluation: Equatable, Sendable {
    let decision: AuthDecision
    let wouldBlock: RuleMatch?
}

/// authResultIsCacheable reports whether a decided AUTH_EXEC verdict may be pinned into the kernel's per-(dev,inode,mtime)
/// AUTH cache via `es_respond_auth_result(..., cache: true)`. Pure and ES-free so the no-EndpointSecurity test target can pin
/// the contract (#209). ApplicationControlStore flushes the kernel cache on every snapshot swap (es_clear_cache via
/// onSnapshotApplied), so caching is safe against a later rule CHANGE; the remaining hazard this guards is caching a verdict
/// that a warm re-evaluation under the SAME snapshot could flip.
///
/// Only a FULLY RESOLVED `.allow` is cacheable. The `.allow` verdict is returned both for a clean walk that consulted the
/// whole identity tuple AND for a fall-through where a lazily-resolved identity component was still cold: a deadline/read
/// failure on the BINARY hash (under a fail-open posture), or a CERTIFICATE rule that silently missed because the leaf cert
/// was not cached yet. Caching such a cold-miss allow would let the kernel short-circuit the very re-exec that would warm the
/// cache and let the BINARY/CERTIFICATE block rule fire, so those stay uncached (issue #209). Concretely, `.allow` is
/// cacheable only when the BINARY hash was computed or not needed AND (the snapshot has no CERTIFICATE rules OR the leaf cert
/// was resolved). DENY and the undecided audit variants are never cached: DENY so removing a block rule takes effect on the
/// next exec, undecided because the identity is not yet known. An allow that matched a DETECT rule is never cached either: a
/// cached verdict never reaches the handler again, so every later exec of the binary would go unreported.
func authResultIsCacheable(
    _ evaluation: AuthEvaluation,
    hashOutcome: HashOutcome,
    leafCertResolved: Bool,
    snapshotHasCertificateRules: Bool
) -> Bool {
    guard case .allow = evaluation.decision, evaluation.wouldBlock == nil else {
        return false
    }
    let hashResolved: Bool
    switch hashOutcome {
    case .computed, .notNeeded:
        hashResolved = true
    case .deadlineExceeded, .readFailed:
        hashResolved = false
    }
    return hashResolved && (!snapshotHasCertificateRules || leafCertResolved)
}

/// evaluateAuthExec walks the precedence ladder against the active snapshot and returns the wire-level decision together with
/// the DETECT rule the exec matched, if any. Pure: no EndpointSecurity imports, no Darwin time calls, no logging side effects
/// on the hot path. Drives the SwiftPM-test surface because ESFSubscriber.swift is excluded from the test target by
/// Package.swift.
///
/// Precedence (Santa's order, every wire-enum rule type wired as of PR for #210):
///   CDHASH > BINARY > CERTIFICATE > SIGNINGID > TEAMID > PATH
///
/// A PROTECT rule ends the walk with a deny. A DETECT rule does not end it: the first DETECT match in precedence order is
/// recorded and the walk goes on, so a DETECT rule never weakens enforcement. The verdict for any exec is the verdict the
/// snapshot would give with its DETECT rules removed; adding a DETECT rule for a binary that a lower-precedence PROTECT rule
/// blocks leaves that binary blocked, and the fallback posture below still governs an unresolved BINARY hash.
///
/// The BINARY layer is gated on hashOutcome: if .computed, walk the BINARY map; if .deadlineExceeded or .readFailed the walk
/// CONTINUES through every lower-precedence layer first, because a definitive lower-precedence DENY dominates the BINARY
/// layer's "could-have-fired" uncertainty (the operator's snapshot tells us the binary identifies as cert X / signing-id Y /
/// team Z / path P; a block rule on any of those is a real verdict the kernel can act on). Only after every layer below BINARY
/// produces no deny does the snapshot's deadlineFallback posture apply to the unresolved BINARY decision. .notNeeded skips
/// BINARY entirely and continues normally (snapshot has no BINARY rules so the fallback posture has nothing to govern).
///
/// PATH is the lowest-trust layer by design: paths are the most operator-spoofable identifier (symlinks, bind mounts, copies
/// preserving content but changing the path string), so a deny higher in the ladder always wins. Santa places PATH last for
/// the same reason; documenting this here so a future precedence reorder is a deliberate decision, not an accident.
///
/// Posture flows from snapshot.deadlineFallback directly: this function does not take a separate posture parameter, so a
/// caller cannot accidentally evaluate one snapshot's rule maps under a different fallback.
func evaluateAuthExec(
    tuple: AuthTuple,
    snapshot: ApplicationControlSnapshot,
    hashOutcome: HashOutcome
) -> AuthEvaluation {
    var walk = PrecedenceWalk()
    if let end = walk.consult(tuple.cdhash, in: snapshot.cdhashRules) {
        return end
    }
    if let end = walk.consult(computedHash(hashOutcome), in: snapshot.binaryRules) {
        return end
    }
    if let end = walk.consult(tuple.leafCertSHA256, in: snapshot.certificateRules) {
        return end
    }
    if let end = walk.consult(tuple.signingIDPrefixed, in: snapshot.signingIDRules) {
        return end
    }
    if let end = walk.consult(tuple.teamID, in: snapshot.teamIDRules) {
        return end
    }
    if let end = walk.consult(tuple.canonicalPath, in: snapshot.pathRules) {
        return end
    }
    if let reason = unresolvedBinaryReason(for: hashOutcome) {
        return walk.finish(applyPosture(snapshot.deadlineFallback, reason: reason))
    }
    return walk.finish(.allow)
}

/// PrecedenceWalk carries the one piece of state a walk accumulates: the first DETECT rule it matched.
private struct PrecedenceWalk {
    private var wouldBlock: RuleMatch?

    /// consult looks one layer's tuple value up in that layer's rule map. It returns the evaluation when the match ends the walk
    /// and nil when the walk goes on, which is the case for no match and for a DETECT match. Rules with an action other than
    /// BLOCK, and any enforcement other than PROTECT or DETECT, are reserved values the server does not create; they end the
    /// walk as "matched but does not deny", as they did before DETECT had a meaning.
    mutating func consult(_ identifier: String?, in rules: [String: ApplicationControlRule]) -> AuthEvaluation? {
        guard let identifier, let rule = rules[identifier] else {
            return nil
        }
        guard rule.action == ApplicationControlAction.block else {
            return finish(.allow)
        }
        switch rule.enforcement {
        case ApplicationControlEnforcement.protect:
            return finish(.deny(rule: rule, matchedIdentifier: identifier))
        case ApplicationControlEnforcement.detect:
            if wouldBlock == nil {
                wouldBlock = RuleMatch(rule: rule, matchedIdentifier: identifier)
            }
            return nil
        default:
            return finish(.allow)
        }
    }

    /// finish pairs the verdict with the recorded DETECT match, dropping the match when the verdict denies.
    func finish(_ decision: AuthDecision) -> AuthEvaluation {
        switch decision {
        case .allow, .allowWithUndecidedAudit:
            return AuthEvaluation(decision: decision, wouldBlock: wouldBlock)
        case .deny, .denyWithUndecidedAudit:
            return AuthEvaluation(decision: decision, wouldBlock: nil)
        }
    }
}

/// computedHash is the BINARY layer's lookup key: the hex SHA-256 when the hash was computed, and nil otherwise, which skips
/// the layer. An unresolved hash is picked up again by unresolvedBinaryReason once every lower layer has been consulted.
private func computedHash(_ hashOutcome: HashOutcome) -> String? {
    if case .computed(let sha) = hashOutcome {
        return sha
    }
    return nil
}

/// unresolvedBinaryReason maps a hash failure to the audit-event reason tag. Returns nil for .computed (a definitive
/// answer either way) and .notNeeded (the snapshot has no BINARY rules so there is nothing for a posture to govern).
/// Drives the deadlineFallback decision after the walker has consulted every lower layer.
private func unresolvedBinaryReason(for hashOutcome: HashOutcome) -> UndecidedReason? {
    switch hashOutcome {
    case .deadlineExceeded:
        return .deadline
    case .readFailed:
        return .readFailed
    case .computed, .notNeeded:
        return nil
    }
}

/// macOSPrivatePrefixes lists the absolute-path prefixes that macOS exposes as `/private/...` symlinks (the `/tmp`, `/var`,
/// `/etc` triple, stable on every macOS version that has shipped Endpoint Security). canonicalizePath rewrites a path
/// starting with any of these into the `/private`-prefixed form to match Foundation's `realpath(3)` output and the
/// server-side Go canonicaliser. Hoisted to file scope so the rewrite loop runs without allocating a fresh array per
/// AUTH_EXEC call (Copilot PR #290) AND so SonarCloud's swift:S1075 hardcoded-URI heuristic has one named constant to look
/// at rather than three inline literals.
private let macOSPrivatePrefixes: [String] = ["/tmp", "/var", "/etc"]

/// privatePrefix is the rewrite target each macOSPrivatePrefixes entry is lifted under. Same purpose for swift:S1075 as
/// macOSPrivatePrefixes above.
private let privatePrefix = "/private"

/// canonicalizePath returns the macOS-canonical form of an absolute path, matching the server-side
/// `server/rules/internal/appcontrol/CanonicalizePath` rules verbatim: rejects empty / relative / `..`-containing paths,
/// collapses redundant slashes (filepath.Clean equivalent), and rewrites the /tmp, /var, /etc symlinks into their
/// /private/... forms. Returns nil for any rejection case so the caller treats the rule as not-applicable rather than
/// generating a falsely-canonicalised match. The Swift and Go implementations MUST stay in lockstep: a rule created
/// against `/tmp/foo` is persisted as `/private/tmp/foo`; AUTH_EXEC must canonicalise the exec target the same way or the
/// rule never matches. Tested in AuthExecDeciderTests so a divergence surfaces at L0.
func canonicalizePath(_ path: String) -> String? {
    if path.isEmpty {
        return nil
    }
    if !path.hasPrefix("/") {
        return nil
    }
    var segments: [String] = []
    for segment in path.split(separator: "/", omittingEmptySubsequences: false) {
        let s = String(segment)
        if s == ".." {
            return nil
        }
        if s.isEmpty || s == "." {
            continue
        }
        segments.append(s)
    }
    let cleaned = "/" + segments.joined(separator: "/")
    for prefix in macOSPrivatePrefixes {
        if cleaned == prefix || cleaned.hasPrefix(prefix + "/") {
            return privatePrefix + cleaned
        }
    }
    return cleaned
}

/// applyPosture is the BINARY-layer fallback when the hash could not be obtained. The three postures encode the operator's
/// choice between enforcement strictness, exec-startup latency, and operational visibility; see FallbackPosture's doc comment
/// for the rationale behind each.
private func applyPosture(_ posture: FallbackPosture, reason: UndecidedReason) -> AuthDecision {
    switch posture {
    case .failClosed:
        return .denyWithUndecidedAudit(reason: reason)
    case .failOpen:
        return .allow
    case .auditOnly:
        return .allowWithUndecidedAudit(reason: reason)
    }
}
