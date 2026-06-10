import EndpointSecurity
import Foundation

// AUTH_EXEC decision-support helpers split out of ESFSubscriber.swift to keep that file under SwiftLint's file_length /
// type_body_length caps (same rationale as the ESFSubscriber+FileEvents.swift / ESFSubscriber+BTM.swift splits). These run
// on the bounded AUTH decision worker (see handleAuthExec, #298) and reach ESFSubscriber's module-internal `serializer` +
// `onEvent`, so they are internal (not private). buildAuthTuple resolves the five pure identifiers the decider reads; the
// emit* helpers serialize the decision's telemetry after the kernel has already been unblocked.

extension ESFSubscriber {
    /// buildAuthTuple reduces a Mach-O exec target to the five pure-identifier values the decider reads. The sixth identifier
    /// (BINARY SHA-256) is supplied via HashOutcome at decide time so the hash compute can run on handleAuthExec's decision
    /// worker under a deadline budget; that responsibility lives in handleAuthExec, not here. The `path` argument is the resolved
    /// executable path used both for the SigningInfoFallback lookups (TeamID + leaf cert SHA-256) and for the canonical PATH
    /// derivation. The leaf cert hash + canonical path joined the tuple when CERTIFICATE / PATH wired through (PR for #210).
    func buildAuthTuple(target: es_process_t, fileStat: stat, path: String) -> AuthTuple {
        let esTeamID = esTokenString(target.team_id)
        let signingID = esTokenString(target.signing_id)

        let cdhash: String? = isHardenedRuntime(flags: target.codesigning_flags) ? cdhashHexString(from: target.cdhash) : nil

        // Resolve the canonical TeamID. For Developer-ID-signed targets on notarized release hosts ESF
        // reports the real team_id and the fallback branch is skipped; the fallback still fires for
        // ad-hoc-signed or unsigned targets even there and correctly returns nil. On the edr-dev VM the
        // extension itself is ad-hoc-signed (`codesign -d` reports `adhoc, linker-signed`); ESF responds
        // by redacting target.team_id="" and forcing target.is_platform_binary=true for EVERY exec the
        // client sees -- a per-client policy on ESF clients whose host extension is not Developer-ID-signed
        // + notarized, not a per-binary CS_PLATFORM_BINARY classification. Quantified on a fresh queue:
        // 393/393 exec events redacted (see issue #187). Without a fallback every TEAMID rule on edr-dev
        // is effectively dead and every SIGNINGID rule degrades to the `platform:<bundle.id>` shape
        // regardless of who actually signed the binary. SigningInfoFallback reads the binary via
        // SecCodeCopySigningInformation -- the same path `codesign -dvv` walks -- and caches the result
        // per (inode, mtime). The fix on a real release host is to notarize the extension; until then the
        // fallback keeps edr-dev usable for end-to-end QA.
        let teamID: String
        if !esTeamID.isEmpty {
            teamID = esTeamID
        } else {
            teamID = SigningInfoFallback.shared.teamID(forPath: path, fileStat: fileStat) ?? ""
        }

        // Leaf certificate SHA-256 always comes from SigningInfoFallback -- ESF does not surface a cert hash directly, so
        // there is no "ESF first, fallback on empty" pattern here. The cache key is shared with the TeamID lookup above so
        // both fields cost one SecCode walk per (inode, mtime). Returns nil for unsigned / ad-hoc-signed binaries and any
        // path SecCode rejects; the decider's optional binding skips the CERTIFICATE layer cleanly in those cases.
        let leafCertSHA256 = SigningInfoFallback.shared.leafCertSHA256(forPath: path, fileStat: fileStat)

        // SIGNINGID prefix: "<TeamID>:<bundle.id>" for third-party signed binaries, "platform:<bundle.id>" for Apple platform
        // binaries. Under edr-dev's ad-hoc-extension redaction ESF reports is_platform_binary=true on every exec (#187), so
        // we use the fallback team_id (when present) to discriminate genuine Apple platform binaries from third-party ones.
        let signingIDPrefixed: String?
        if signingID.isEmpty {
            signingIDPrefixed = nil
        } else if !teamID.isEmpty {
            signingIDPrefixed = "\(teamID):\(signingID)"
        } else if target.is_platform_binary {
            signingIDPrefixed = "platform:\(signingID)"
        } else {
            signingIDPrefixed = nil
        }

        // Canonical path: filepath.Clean equivalent + /tmp + /var + /etc rewritten to /private. MUST match the server-side
        // CanonicalizePath rules exactly or rules persisted in canonical form never match what the AUTH callback computes.
        // Nil result (empty / relative / `..`-containing -- all defensive against malformed ESF input) skips the PATH layer.
        let canonicalPath = canonicalizePath(path)

        return AuthTuple(
            cdhash: cdhash,
            leafCertSHA256: leafCertSHA256,
            signingIDPrefixed: signingIDPrefixed,
            teamID: teamID.isEmpty ? nil : teamID,
            canonicalPath: canonicalPath
        )
    }

    /// emitBlockEvent serializes an application_control_block event for the
    /// just-denied AUTH_EXEC and hands it to the upload pipeline via
    /// onEvent. Called after the DENY response so the kernel is already
    /// unblocked; the JSON encode + XPC handoff happen off the callback's
    /// deadline.
    func emitBlockEvent(
        target: es_process_t,
        rule: ApplicationControlRule,
        matchedIdentifier: String,
        snapshot: ApplicationControlSnapshot
    ) {
        let pid = audit_token_to_pid(target.audit_token)
        let path = esTokenString(target.executable.pointee.path)
        let payload = ApplicationControlBlockPayload(
            pid: pid,
            path: path,
            ruleID: rule.ruleID,
            ruleType: rule.ruleType,
            identifier: matchedIdentifier,
            severity: rule.severity,
            customMsg: rule.customMsg,
            customURL: rule.customURL,
            policyID: snapshot.policyID,
            policyVersion: snapshot.policyVersion
        )
        if let data = serializer.serialize(eventType: "application_control_block", payload: payload) {
            onEvent?(data)
        }
    }

    /// emitUndecidedEvent serializes an application_control_undecided event for an AUTH_EXEC whose BINARY hash could not be
    /// resolved within the kernel deadline budget (or the file was unreadable). Called after the kernel respond so the post-
    /// respond cost does not eat into the deadline. The verdict argument carries "allow" (audit-only posture) or "deny"
    /// (fail-closed posture); fail-open does NOT call this helper (no event by design, see FallbackPosture.failOpen).
    func emitUndecidedEvent(
        target: es_process_t,
        fileStat: stat,
        verdict: String,
        reason: UndecidedReason,
        snapshot: ApplicationControlSnapshot
    ) {
        let pid = audit_token_to_pid(target.audit_token)
        let path = esTokenString(target.executable.pointee.path)
        let payload = ApplicationControlUndecidedPayload(
            pid: pid,
            path: path,
            verdict: verdict,
            reason: reason.rawValue,
            fileSizeBytes: UInt64(fileStat.st_size),
            policyID: snapshot.policyID,
            policyVersion: snapshot.policyVersion
        )
        if let data = serializer.serialize(eventType: "application_control_undecided", payload: payload) {
            onEvent?(data)
        }
    }

    /// emitBlockNotification fires the desktop-notification XPC
    /// message to the host app's listener. Called after the DENY
    /// response so the kernel is already unblocked; the alert is
    /// post-hoc UX. Fire-and-forget: NotificationClient swallows
    /// errors so a missing host app (the LaunchAgent hasn't
    /// started yet, or the user logged out) doesn't slow the
    /// AUTH_EXEC handler down.
    func emitBlockNotification(
        target: es_process_t,
        rule: ApplicationControlRule,
        matchedIdentifier: String,
        snapshot: ApplicationControlSnapshot
    ) {
        let path = esTokenString(target.executable.pointee.path)
        let payload = BlockNotificationPayload(
            ruleID: rule.ruleID,
            ruleType: rule.ruleType,
            identifier: matchedIdentifier,
            customMsg: rule.customMsg,
            customURL: rule.customURL,
            binaryPath: path,
            policyID: snapshot.policyID,
            policyVersion: snapshot.policyVersion
        )
        NotificationClient.shared.notify(payload)
    }
}
