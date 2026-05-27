import EndpointSecurity
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFSubscriber")

/// Self-allow failsafe inputs: AUTH_EXEC exempts Fleet's own components from app-control enforcement only when target.team_id
/// matches extensionTeamID AND target.signing_id is in fleetSelfAllowSigningIDs. Team-id-only would exempt every binary Fleet
/// has ever signed. Phase B replaces both with a server-pushed allowlist so operators can extend without an agent re-release.
private let extensionTeamID = "FDG8Q7N4CC"

private let fleetSelfAllowSigningIDs: Set<String> = [
    "com.fleetdm.edr.agent",
    "com.fleetdm.edr.securityextension",
    "com.fleetdm.edr.networkextension",
    "com.fleetdm.edr"
]

/// ESFSubscriber manages the Endpoint Security client and subscribes to
/// process lifecycle events (exec, fork, exit, open).
final class ESFSubscriber: Sendable {
    // swiftlint:disable:next implicitly_unwrapped_optional
    private nonisolated(unsafe) var client: OpaquePointer!
    private let serializer = EventSerializer()
    nonisolated(unsafe) var onEvent: ((Data) -> Void)?

    init() {
        var rawClient: OpaquePointer?

        let result = es_new_client(&rawClient) { [weak self] _, message in
            self?.handleMessage(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let rawClient else {
            logger.error("Failed to create ES client: \(result.rawValue)")
            exit(EXIT_FAILURE)
        }

        self.client = rawClient
    }

    func start() {
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,    // authorization: allows us to block specific binaries
            ES_EVENT_TYPE_NOTIFY_EXEC,  // notification: records allowed execs (fires after AUTH allows)
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_OPEN
        ]

        let subResult = es_subscribe(client, events, UInt32(events.count))
        guard subResult == ES_RETURN_SUCCESS else {
            logger.error("Failed to subscribe to events: \(subResult.rawValue)")
            exit(EXIT_FAILURE)
        }

        logger.info("Subscribed to \(events.count) event types (including AUTH_EXEC)")
        // Application Control Phase B close-out (PR for #210): AUTH_EXEC consults
        // the ApplicationControlStore snapshot and denies execs matching any of
        // the six wire-enum rule types in fixed Santa precedence:
        //   CDHASH → BINARY → CERTIFICATE → SIGNINGID → TEAMID → PATH.
        // CERTIFICATE matches the SHA-256 of the leaf signing certificate
        // (SecCodeCopySigningInformation walk, cached per (inode, mtime) on first
        // exec). PATH matches the canonical absolute path of the exec target,
        // with /tmp + /var + /etc rewritten to /private/... to match the
        // server-side persisted canonical form. Cache misses on the lazy file-
        // hash cache use the snapshot's deadlineFallback posture for the BINARY
        // layer only; the cheaper CERTIFICATE / SIGNINGID / TEAMID / PATH layers
        // run unconditionally and a definitive deny on any of them dominates
        // BINARY-layer uncertainty.
        logger.info("Application Control active: AUTH_EXEC walks CDHASH/BINARY/CERTIFICATE/SIGNINGID/TEAMID/PATH rules")
    }

    func stop() {
        es_unsubscribe_all(client)
        es_delete_client(client)
    }

    private func handleMessage(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee

        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleAuthExec(message)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            handleExec(msg)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            handleFork(msg)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            handleExit(msg)
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            handleOpen(msg)
        default:
            break
        }
    }

    /// AUTH_EXEC handler. Decision order: (1) platform-binary carve-out (#205) ALLOWs Apple system binaries with cache:true to
    /// avoid bricking the host on an admin-applied BINARY rule for launchd/xpcproxy/etc; (2) self-allow failsafe ALLOWs the
    /// agent + extensions + host app uncached (team_id + bundle-id match); (3) decideAuthExec walks CDHASH → BINARY →
    /// CERTIFICATE → SIGNINGID → TEAMID → PATH (Phase B close-out, PR for #210). BINARY hashing runs synchronously under a
    /// budget derived from msg.deadline (#208 close-out); on deadline / read failure the walk continues through every lower
    /// layer first and only applies the snapshot's deadlineFallback posture when no later rule matches. CERTIFICATE +
    /// SIGNINGID + TEAMID rely on SigningInfoFallback's cached SecCode walk; PATH uses canonicalizePath on the exec target
    /// path so the in-memory comparison matches the server-side persisted canonical form verbatim.
    private func handleAuthExec(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let target = msg.event.exec.target.pointee
        let path = esTokenString(target.executable.pointee.path)
        let teamID = esTokenString(target.team_id)
        let signingID = esTokenString(target.signing_id)
        let fileStat = target.executable.pointee.stat

        // Platform-binary carve-out: anything the kernel classifies as part of the Apple-signed system image (launchd, xpcproxy,
        // fseventsd, kextd, sysextd, systemextensionsd, WindowServer, loginwindow, mds, ...) is ALLOWed unconditionally and the
        // result is pinned into the kernel's per-(dev,inode,mtime) AUTH cache. This is the floor against an admin who pastes the
        // SHA-256 of /sbin/launchd into a BINARY block rule and bricks the host on next boot. The kernel's own is_platform_binary
        // flag is more conservative than a hand-curated path or signing-id allowlist would be, and the answer is intrinsic to the
        // binary's identity, so caching the ALLOW is safe (mtime mutation forces a fresh decision).
        if target.is_platform_binary {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true)
            return
        }

        // Self-allow failsafe: exempt the agent + extensions + host app from app-control enforcement so a misconfigured rule cannot
        // brick the EDR itself. Match BOTH team_id and the exhaustive Fleet bundle-id set; team_id alone would exempt every binary
        // ever signed by extensionTeamID, which is broader than intended.
        if teamID == extensionTeamID, fleetSelfAllowSigningIDs.contains(signingID) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let snapshot = ApplicationControlStore.shared.currentSnapshot()
        let tuple = buildAuthTuple(target: target, fileStat: fileStat, path: path)

        // Only pay the sync-hash cost when the snapshot actually has BINARY rules to consult. The cheap CDHASH/SIGNINGID/TEAMID
        // layers run unconditionally; the hash compute alone is the latency outlier (tens of ms on multi-MB binaries) and is
        // wasted work when no BINARY rule could fire.
        let hashOutcome: HashOutcome
        if snapshot.binaryRules.isEmpty {
            hashOutcome = .notNeeded
        } else {
            hashOutcome = FileHashCache.shared.lookupOrComputeWithDeadline(
                path: path,
                stat: fileStat,
                deadlineMachAbs: msg.deadline
            )
        }

        let decision = decideAuthExec(tuple: tuple, snapshot: snapshot, hashOutcome: hashOutcome)
        dispatchAuthDecision(decision, context: AuthDispatchContext(
            message: message, target: target, fileStat: fileStat, snapshot: snapshot, path: path
        ))
    }

    /// AuthDispatchContext bundles the fields dispatchAuthDecision needs into a single argument so the function stays under
    /// SwiftLint's function_parameter_count limit. Fields are wire-side (es_process_t / stat) and live here rather than in
    /// AuthExecDecider.swift because they pull in EndpointSecurity types the SwiftPM test target deliberately excludes.
    private struct AuthDispatchContext {
        let message: UnsafePointer<es_message_t>
        let target: es_process_t
        let fileStat: stat
        let snapshot: ApplicationControlSnapshot
        let path: String
    }

    /// dispatchAuthDecision turns the pure-logic AuthDecision into the wire-level kernel response plus any event/notification
    /// emissions the decision implies. Extracted from handleAuthExec so the decision logic stays testable
    /// (AuthExecDeciderTests) and the wire dispatch stays one switch.
    private func dispatchAuthDecision(_ decision: AuthDecision, context: AuthDispatchContext) {
        switch decision {
        case .allow:
            es_respond_auth_result(client, context.message, ES_AUTH_RESULT_ALLOW, false)
        case .allowWithUndecidedAudit(let reason):
            logger.warning("AUTH_EXEC ALLOW (undecided) reason=\(reason.rawValue, privacy: .public)")
            es_respond_auth_result(client, context.message, ES_AUTH_RESULT_ALLOW, false)
            emitUndecidedEvent(
                target: context.target, fileStat: context.fileStat, verdict: "allow", reason: reason, snapshot: context.snapshot
            )
        case .deny(let rule, let matchedIdentifier):
            logger.warning(
                "AUTH_EXEC DENIED type=\(rule.ruleType, privacy: .public) id=\(matchedIdentifier, privacy: .public)"
            )
            es_respond_auth_result(client, context.message, ES_AUTH_RESULT_DENY, false)
            emitBlockEvent(
                target: context.target, rule: rule, matchedIdentifier: matchedIdentifier, snapshot: context.snapshot
            )
            emitBlockNotification(
                target: context.target, rule: rule, matchedIdentifier: matchedIdentifier, snapshot: context.snapshot
            )
        case .denyWithUndecidedAudit(let reason):
            logger.warning("AUTH_EXEC DENIED (undecided) reason=\(reason.rawValue, privacy: .public)")
            es_respond_auth_result(client, context.message, ES_AUTH_RESULT_DENY, false)
            emitUndecidedEvent(
                target: context.target, fileStat: context.fileStat, verdict: "deny", reason: reason, snapshot: context.snapshot
            )
        }
    }

    /// buildAuthTuple reduces a Mach-O exec target to the five pure-identifier values the decider reads. The sixth identifier
    /// (BINARY SHA-256) is supplied via HashOutcome at decide time so the hash compute can run on the AUTH callback thread
    /// under a deadline budget; that responsibility lives in handleAuthExec, not here. The `path` argument is the resolved
    /// executable path used both for the SigningInfoFallback lookups (TeamID + leaf cert SHA-256) and for the canonical PATH
    /// derivation. The leaf cert hash + canonical path joined the tuple when CERTIFICATE / PATH wired through (PR for #210).
    private func buildAuthTuple(target: es_process_t, fileStat: stat, path: String) -> AuthTuple {
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
    private func emitBlockEvent(
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
    private func emitUndecidedEvent(
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
    /// post-hoc UX. Fire-and-forget — NotificationClient swallows
    /// errors so a missing host app (the LaunchAgent hasn't
    /// started yet, or the user logged out) doesn't slow the
    /// AUTH_EXEC handler down.
    private func emitBlockNotification(
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

    private func handleExec(_ msg: es_message_t) {
        let process = msg.process.pointee
        var exec = msg.event.exec

        // Use the exec target for PID, path, and code signing — msg.process
        // is the process *before* the exec (e.g., xpcproxy), while
        // exec.target is the new executable being loaded.
        let target = exec.target.pointee
        let pid = audit_token_to_pid(target.audit_token)
        let ppid = audit_token_to_pid(process.parent_audit_token)
        let path = String(cString: target.executable.pointee.path.data)
        let args = extractArgs(from: &exec)
        let uid = audit_token_to_euid(target.audit_token)
        let gid = audit_token_to_egid(target.audit_token)
        let fileStat = target.executable.pointee.stat

        let codeSigning = extractCodeSigning(from: target)
        // NOTIFY_EXEC has no kernel deadline, so the sync compute is the
        // right call here — every event carries a real hash for downstream
        // telemetry. The AUTH callback (which has a deadline) already
        // started a lazy fill for the same (inode, mtime), so the common
        // case is a cache hit. lookupOrCompute returns nil when the file
        // is gone or unreadable (deleted-between-AUTH-and-NOTIFY race);
        // the event still fires with the rest of the metadata.
        let sha256 = FileHashCache.shared.lookupOrCompute(path: path, stat: fileStat)
        // CDHash is present only when the binary uses Hardened Runtime (per Phase A close-out spec). Server-side detection
        // rules and the future leaf-cert correlator both consume this when available; absent for non-hardened binaries.
        let cdhash: String? = isHardenedRuntime(flags: target.codesigning_flags) ? cdhashHexString(from: target.cdhash) : nil

        let payload = ExecPayload(
            pid: pid,
            ppid: ppid,
            path: path,
            args: args,
            cwd: "", // es_process_t has no cwd member on macOS 26 SDK
            uid: uid,
            gid: gid,
            codeSigning: codeSigning,
            sha256: sha256,
            cdhash: cdhash
        )

        if let data = serializer.serialize(eventType: "exec", payload: payload) {
            logger.debug("exec pid=\(pid) path=\(path)")
            onEvent?(data)
        }
    }

    private func handleFork(_ msg: es_message_t) {
        let childPid = audit_token_to_pid(msg.event.fork.child.pointee.audit_token)
        let parentPid = audit_token_to_pid(msg.process.pointee.audit_token)

        let payload = ForkPayload(childPid: childPid, parentPid: parentPid)

        if let data = serializer.serialize(eventType: "fork", payload: payload) {
            logger.debug("fork parent=\(parentPid) child=\(childPid)")
            onEvent?(data)
        }
    }

    private func handleExit(_ msg: es_message_t) {
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        let exitCode = msg.event.exit.stat

        let payload = ExitPayload(pid: pid, exitCode: Int(exitCode))

        if let data = serializer.serialize(eventType: "exit", payload: payload) {
            logger.debug("exit pid=\(pid) code=\(exitCode)")
            onEvent?(data)
        }
    }

    private func handleOpen(_ msg: es_message_t) {
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        let path = String(cString: msg.event.open.file.pointee.path.data)
        let flags = msg.event.open.fflag

        let payload = OpenPayload(pid: pid, path: path, flags: Int(flags))

        if let data = serializer.serialize(eventType: "open", payload: payload) {
            logger.debug("open pid=\(pid) path=\(path)")
            onEvent?(data)
        }
    }

    private func extractArgs(from exec: inout es_event_exec_t) -> [String] {
        let count = es_exec_arg_count(&exec)
        var args: [String] = []
        for i in 0..<count {
            let arg = es_exec_arg(&exec, i)
            args.append(String(cString: arg.data))
        }
        return args
    }

    private func extractCodeSigning(from process: es_process_t) -> CodeSigning? {
        let teamID = process.team_id.data.map { String(cString: $0) }
        let signingID = process.signing_id.data.map { String(cString: $0) }

        guard teamID != nil || signingID != nil else {
            return nil
        }

        return CodeSigning(
            teamID: teamID ?? "",
            signingID: signingID ?? "",
            flags: process.codesigning_flags,
            isPlatformBinary: process.is_platform_binary
        )
    }
}

// isHardenedRuntime + cdhashHexString helpers moved to CDHashHex.swift (PR for #210) to keep this file under SwiftLint's
// file_length cap. The helpers are pure; ESFSubscriber consumes them via their module-internal symbols (Swift's implicit
// `internal` access — no explicit modifier is required since both files compile into the same module).
