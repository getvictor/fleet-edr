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
/// the on-disk handle. The decider is pure -- it consumes the outcome and returns a decision.
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
/// optional: absent values mean "the target has no value of this kind", and the precedence walker skips that map. CERTIFICATE
/// and PATH stay deferred to Phase B and are not present here. Sendable so callers can build the tuple on the AUTH callback
/// thread and hand it to a future async pipeline without bridging tricks.
struct AuthTuple: Equatable, Sendable {
    /// 40-char lowercase hex CDHash, only when the target runs under Apple's Hardened Runtime (CS_RUNTIME); see the comment on
    /// isHardenedRuntime in ESFSubscriber.swift for the lazy-page-mapping rationale.
    let cdhash: String?
    /// "<TeamID>:<bundle.id>" for third-party signed binaries, "platform:<bundle.id>" for kernel-classified Apple platform
    /// binaries. nil when ESF reports neither a usable team_id (real or fallback) nor a platform classification.
    let signingIDPrefixed: String?
    /// 10-char Apple Developer Team ID. nil when ESF redacts team_id (ad-hoc-signed extension on edr-dev) and
    /// SigningInfoFallback also cannot recover a real value.
    let teamID: String?
}

/// AuthDecision is the discrete verdict the wire side dispatches on. Cases enumerate every action handleAuthExec can take short
/// of the kernel-cached platform-binary carve-out and the unconditional self-allow failsafe (both short-circuit before the
/// decider runs).
enum AuthDecision: Equatable, Sendable {
    /// Allow the exec; do NOT pin the result into the kernel AUTH cache. Used when no rule matched and the hash either was not
    /// needed (no BINARY rules) or returned a clean miss against the BINARY map. Uncached because a later rule update could
    /// turn this exec into a block on the next run; a kernel-cached ALLOW would skip our handler entirely.
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

/// decideAuthExec walks the precedence ladder against the active snapshot and returns the wire-level decision. Pure: no
/// EndpointSecurity imports, no Darwin time calls, no logging side effects on the hot path. Drives the SwiftPM-test surface
/// because ESFSubscriber.swift is excluded from the test target by Package.swift.
///
/// Precedence: CDHASH > BINARY > SIGNINGID > TEAMID. CERTIFICATE + PATH stay deferred to Phase B and are not consulted here.
/// Each layer returns on first match. The BINARY layer is gated on hashOutcome: if .computed, walk the BINARY map; if
/// .deadlineExceeded or .readFailed the walk CONTINUES to SIGNINGID/TEAMID first -- a definitive lower-precedence DENY
/// dominates the BINARY layer's "could-have-fired" uncertainty (the operator's snapshot tells us the binary identifies as
/// signing-id X / team Y; a block rule on X or Y is a real verdict the kernel can act on). Only after SIGNINGID/TEAMID
/// produce no match does the snapshot's deadlineFallback posture apply to the unresolved BINARY decision. .notNeeded skips
/// BINARY entirely and continues normally (snapshot has no BINARY rules so the fallback posture has nothing to govern).
///
/// Posture flows from snapshot.deadlineFallback directly -- this function does not take a separate posture parameter, so a
/// caller cannot accidentally evaluate one snapshot's rule maps under a different fallback. (Previous signatures took the
/// parameter explicitly; the round-trip through snapshot already pins the posture, so the parameter was a footgun.)
func decideAuthExec(
    tuple: AuthTuple,
    snapshot: ApplicationControlSnapshot,
    hashOutcome: HashOutcome
) -> AuthDecision {
    if let cdhash = tuple.cdhash, let rule = snapshot.cdhashRules[cdhash] {
        return verdict(for: rule, identifier: cdhash)
    }

    var unresolvedBinaryReason: UndecidedReason?
    switch hashOutcome {
    case .computed(let sha):
        if let rule = snapshot.binaryRules[sha] {
            return verdict(for: rule, identifier: sha)
        }
    case .deadlineExceeded:
        unresolvedBinaryReason = .deadline
    case .readFailed:
        unresolvedBinaryReason = .readFailed
    case .notNeeded:
        break
    }

    if let signingID = tuple.signingIDPrefixed, let rule = snapshot.signingIDRules[signingID] {
        return verdict(for: rule, identifier: signingID)
    }
    if let teamID = tuple.teamID, let rule = snapshot.teamIDRules[teamID] {
        return verdict(for: rule, identifier: teamID)
    }

    if let reason = unresolvedBinaryReason {
        return applyPosture(snapshot.deadlineFallback, reason: reason)
    }
    return .allow
}

/// verdict maps a matched rule to the wire-level decision. Non-PROTECT enforcements (DETECT) and non-BLOCK actions (ALLOW,
/// SILENT_BLOCK) are no-ops in v0.1.0: the precedence walker treats them as "matched but does not deny." DETECT semantics
/// arrive in the follow-on add-application-control-detect-mode change, which extends this helper to emit a detection event
/// alongside the ALLOW.
private func verdict(for rule: ApplicationControlRule, identifier: String) -> AuthDecision {
    if rule.action == ApplicationControlAction.block && rule.enforcement == ApplicationControlEnforcement.protect {
        return .deny(rule: rule, matchedIdentifier: identifier)
    }
    return .allow
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
