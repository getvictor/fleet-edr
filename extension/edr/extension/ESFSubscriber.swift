import EndpointSecurity
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFSubscriber")

/// Our Apple Developer Team ID. The self-allow failsafe (AUTH_EXEC) requires both
/// this team_id AND a fleetSelfAllowSigningIDs membership; matching team_id alone
/// would exempt every binary signed by Fleet (including any legacy or unrelated
/// utility sharing the cert). Phase B replaces this with a server-pushed failsafe
/// list so operators can extend it without an agent re-release.
private let extensionTeamID = "FDG8Q7N4CC"

/// fleetSelfAllowSigningIDs is the exhaustive set of Fleet EDR bundle identifiers the
/// AUTH_EXEC failsafe exempts from app-control enforcement: the agent daemon, the two
/// system extensions, and the host app. A binary whose signing_id is NOT on this list
/// is subject to the precedence walker even if signed by extensionTeamID. Hardcoded
/// for the Phase A close-out; Phase B server-pushes the same list so operators can
/// extend it for in-house tooling without an agent re-release.
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
        // Application Control Phase A close-out: AUTH_EXEC consults the
        // ApplicationControlStore snapshot and denies execs matching any of
        // four rule types in fixed precedence: CDHASH → BINARY → SIGNINGID →
        // TEAMID. CERTIFICATE + PATH stay deferred to Phase B (leaf-cert cache
        // / Launch Services indirection). Cache misses on the lazy file-hash
        // cache return ALLOW silently for the BINARY type; the cache fills
        // off the callback so the next exec of the same binary catches.
        logger.info("Application Control active: AUTH_EXEC walks CDHASH/BINARY/SIGNINGID/TEAMID rules")
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

    /// AUTH_EXEC handler: application-control decision walk.
    ///
    /// Walks four rule types in fixed precedence: CDHASH → BINARY → SIGNINGID → TEAMID.
    /// CERTIFICATE and PATH stay deferred to Phase B (leaf-cert cache / Launch Services
    /// indirection). Returns on the first match. Decisions, in order:
    ///   - Platform-binary carve-out: if the kernel sets target.is_platform_binary, ALLOW
    ///     with cache:true. Prevents an admin who writes the SHA-256 of /sbin/launchd
    ///     (or xpcproxy, fseventsd, kextd, sysextd, etc.) as a BINARY block rule from
    ///     bricking the host. The kernel's own "this is on the Apple-signed system image"
    ///     flag is the floor; the answer is intrinsic to the binary's identity so it is
    ///     safe to cache for the file's (dev, inode, mtime) lifetime.
    ///   - Self-allow failsafe: if team_id matches our extensionTeamID AND signing_id is
    ///     on the Fleet bundle-id allowlist, ALLOW. Protects the agent / extensions /
    ///     host app from a misconfigured rule. Uncached so future rules can target Fleet
    ///     binaries for telemetry (e.g. DETECT) without a kernel cache stale-read.
    ///     Phase B replaces this with a server-pushed failsafe list.
    ///   - Precedence walk (CDHASH → BINARY → SIGNINGID → TEAMID): first matching rule
    ///     with `action=BLOCK` and `enforcement=PROTECT` → DENY. Any other enforcement
    ///     ALLOWs (DETECT semantics arrive in the follow-on detect-mode change). The
    ///     BINARY layer needs the file's SHA-256; that hash is computed synchronously on
    ///     the AUTH callback thread under a budget bounded by msg.deadline (closing the
    ///     #208 first-exec cold-cache bypass). If the hash cannot complete in time the
    ///     snapshot's deadlineFallback posture (fail-closed / fail-open / audit-only)
    ///     drives the verdict and an application_control_undecided event lets operators
    ///     audit the cold-cache rate.
    ///   - No match → ALLOW.
    ///
    /// The leaf-cert SHA-256 needed for CERTIFICATE rules is NOT fetched here; CERTIFICATE
    /// matching is gated to Phase B.
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

        let decision = decideAuthExec(
            tuple: tuple,
            snapshot: snapshot,
            hashOutcome: hashOutcome,
            posture: snapshot.deadlineFallback
        )
        dispatchAuthDecision(decision, message: message, target: target, fileStat: fileStat, snapshot: snapshot, path: path)
    }

    /// dispatchAuthDecision turns the pure-logic AuthDecision into the wire-level kernel response plus any event/notification
    /// emissions the decision implies. Extracted from handleAuthExec so the decision logic stays testable (AuthExecDeciderTests)
    /// and the wire dispatch stays one switch. The `path` value is the redacted (privacy: redacted) log identifier; the full path
    /// flows on the block event payload for the server-side alert.
    private func dispatchAuthDecision(
        _ decision: AuthDecision,
        message: UnsafePointer<es_message_t>,
        target: es_process_t,
        fileStat: stat,
        snapshot: ApplicationControlSnapshot,
        path: String
    ) {
        switch decision {
        case .allow:
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        case .allowWithUndecidedAudit(let reason):
            logger.warning("AUTH_EXEC ALLOW (undecided) path=\(path) reason=\(reason.rawValue, privacy: .public)")
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            emitUndecidedEvent(target: target, fileStat: fileStat, verdict: "allow", reason: reason, snapshot: snapshot)
        case .deny(let rule, let matchedIdentifier):
            let denyRuleType = rule.ruleType
            let denyID = matchedIdentifier
            logger.warning(
                "AUTH_EXEC DENIED path=\(path) type=\(denyRuleType, privacy: .public) id=\(denyID, privacy: .public)"
            )
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            emitBlockEvent(target: target, rule: rule, matchedIdentifier: matchedIdentifier, snapshot: snapshot)
            emitBlockNotification(target: target, rule: rule, matchedIdentifier: matchedIdentifier, snapshot: snapshot)
        case .denyWithUndecidedAudit(let reason):
            logger.warning("AUTH_EXEC DENIED (undecided) path=\(path) reason=\(reason.rawValue, privacy: .public)")
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            emitUndecidedEvent(target: target, fileStat: fileStat, verdict: "deny", reason: reason, snapshot: snapshot)
        }
    }

    /// buildAuthTuple reduces a Mach-O exec target to the three pure-identifier values the decider reads. The fourth identifier
    /// (BINARY SHA-256) is supplied via HashOutcome at decide time so the hash compute can run on the AUTH callback thread
    /// under a deadline budget; that responsibility lives in handleAuthExec, not here. The `path` argument is the resolved
    /// executable path used for the SigningInfoFallback lookup when ESF redacts team_id on ad-hoc-signed extension hosts.
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

        // SIGNINGID is prefixed: "<TeamID>:<bundle.id>" for third-party signed binaries,
        // "platform:<bundle.id>" for Apple platform binaries (those whose is_platform_binary flag is set).
        // The server's validator accepts both shapes. Under the ad-hoc-extension redaction described above
        // ESF reports is_platform_binary=true even for unambiguously third-party binaries (Developer ID
        // signed `gh` was the issue #187 reproducer); the fallback team_id is what separates a genuine
        // Apple platform binary (real `platform:` prefix) from a third-party one that should carry the
        // "<TeamID>:<bundle.id>" prefix. Without that branch the SIGNINGID walk on edr-dev would lose its
        // discriminator alongside TEAMID.
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

        return AuthTuple(
            cdhash: cdhash,
            signingIDPrefixed: signingIDPrefixed,
            teamID: teamID.isEmpty ? nil : teamID
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

/// csRuntimeFlag is the codesigning_flags bit set when a binary runs under Apple's Hardened Runtime. Defined here (rather than
/// imported from <kern/cs_blobs.h>) because the Swift bridging headers do not surface the constant directly; the literal value
/// is stable per the public macOS code-signing documentation. Lowercased to satisfy SwiftLint's identifier_name rule (CS_RUNTIME
/// would be the literal C symbol but Swift conventions reject all-caps identifiers).
private let csRuntimeFlag: UInt32 = 0x0001_0000

/// isHardenedRuntime reports whether the codesigning_flags bitfield indicates Apple's Hardened Runtime. CDHASH rules only match
/// hardened-runtime processes because on non-hardened processes the kernel maps pages lazily and does not re-verify them post-load,
/// which makes the CDHash ESF reports at exec an unreliable identity for the bytes that will eventually execute. This diverges from
/// Santa, which enforces CDHASH on any signed binary regardless of the runtime flag; a migrating Santa admin should expect a CDHASH
/// rule to no-op here against a non-hardened target until that target is rebuilt with the Hardened Runtime flag.
private func isHardenedRuntime(flags: UInt32) -> Bool {
    return (flags & csRuntimeFlag) != 0
}

/// hexCharsPerByte is the fixed expansion ratio of a byte to its 2-char lowercase hex representation. Extracted so the capacity
/// reserve in cdhashHexString is self-documenting (SwiftLint's no_magic_numbers rule would otherwise flag the literal `2`).
private let hexCharsPerByte = 2

/// hexDigitsLowercase is the lookup table cdhashHexString walks instead of calling String(format:"%02x", b). The format-string path
/// bridges to Foundation and parses the format spec on every call; this matters because the helper runs inside AUTH_EXEC's
/// kernel-deadline window. The table is private so it doesn't pollute symbol search at the module level.
private let hexDigitsLowercase: [Character] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"
]

/// hexLowNibbleMask is the bitmask used to extract the low 4 bits of a byte when looking up its hex digit in the
/// hexDigitsLowercase table. Named so the no_magic_numbers SwiftLint rule doesn't flag the literal 0x0f.
private let hexLowNibbleMask: UInt8 = 0x0f

// swiftlint:disable large_tuple
//
// cdhashHexString lowercases-hex the 20-byte CDHash array from es_process_t.cdhash into the 40-char string the server's validator
// + the snapshot's cdhashRules map index on. Returns nil when the cdhash is all zero (es_process_t conventions: unsigned binaries
// report a zeroed cdhash, which is not a real identity).
//
// The parameter is a 20-element tuple because the C surface (es_process_t.cdhash) is a fixed-size array that Swift imports as a
// homogeneous tuple. The large_tuple lint is disabled around this declaration because the shape is dictated by the ESF SDK and
// cannot be reshaped without breaking the C bridge.
private func cdhashHexString(from cdhash: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                                            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)) -> String? {
    var bytes = cdhash
    return withUnsafeBytes(of: &bytes) { raw -> String? in
        // All-zero cdhash means "no real CDHash present" — unsigned or otherwise unverifiable. Return nil so the precedence walker
        // skips the CDHASH map for this exec rather than matching a rule whose identifier is "00…00" by coincidence.
        if raw.allSatisfy({ $0 == 0 }) {
            return nil
        }
        var s = ""
        s.reserveCapacity(raw.count * hexCharsPerByte)
        for b in raw {
            s.append(hexDigitsLowercase[Int(b >> 4)])
            s.append(hexDigitsLowercase[Int(b & hexLowNibbleMask)])
        }
        return s
    }
}
// swiftlint:enable large_tuple
