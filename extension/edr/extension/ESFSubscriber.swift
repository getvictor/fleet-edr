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

/// authWorkerConcurrency bounds how many AUTH_EXEC decisions hash/decide in parallel off the ES delivery thread (#298). The
/// ES client delivers AUTH messages on a single serial queue; running the SecCode walk + SHA-256 inline there lets one slow
/// hash stall (and, past the kernel deadline, fail-closed DENY) every queued exec. Offloading to this many concurrent workers
/// breaks that head-of-line blocking while staying low enough not to trade it for a disk-I/O storm during the cold-cache /
/// dual-client window an in-place extension upgrade creates (the original incident). 4 is a conservative, tunable default.
private let authWorkerConcurrency = 4

/// RetainedAuthMessage owns an es_retain_message'd AUTH_EXEC message for the lifetime of a decision worker (#298). RAII: init
/// retains, deinit releases, exactly once — so the message is released whether the operation runs to completion or is ever
/// dropped before responding (a struct + `defer` would leak the message on the drop/cancel path, Gemini). final + @unchecked
/// Sendable: the worker is the sole owner between retain and release, so there is no shared mutation of the pointee.
private final class RetainedAuthMessage: @unchecked Sendable {
    let message: UnsafePointer<es_message_t>
    init(_ message: UnsafePointer<es_message_t>) {
        self.message = message
        es_retain_message(message)
    }
    deinit {
        es_release_message(message)
    }
}

/// maxAuthDecisionBacklog caps how many AUTH_EXEC decisions may be queued/in-flight on authDecisionQueue before handleAuthExec
/// decides inline instead of offloading (#298). maxConcurrentOperationCount bounds parallel WORKERS, not queue DEPTH; without
/// this cap an exec storm would es_retain_message + enqueue without limit, growing an unbounded backlog of retained messages
/// whose deadlines expire while they wait (CodeRabbit). On saturation we degrade to the pre-#298 inline path for the excess —
/// strictly no worse than the old serial behaviour, and self-limiting since the kernel blocks each exec'ing thread until we
/// respond. 128 is far above normal concurrent-exec depth. handleAuthExec runs on the single serial ES delivery thread, so
/// reading operationCount here is race-free.
private let maxAuthDecisionBacklog = 128

/// ESFSubscriber manages the Endpoint Security client and subscribes to
/// process lifecycle events (exec, fork, exit, open).
final class ESFSubscriber: Sendable {
    // swiftlint:disable:next implicitly_unwrapped_optional
    private nonisolated(unsafe) var client: OpaquePointer!
    // Internal (not private) so the file-event handlers split into ESFSubscriber+FileEvents.swift can reach it; that
    // split keeps this file under SwiftLint's file_length / type_body_length caps (same rationale as CDHashHex.swift).
    let serializer = EventSerializer()
    nonisolated(unsafe) var onEvent: ((Data) -> Void)?

    // authDecisionQueue runs the expensive AUTH_EXEC decision (SecCode walk + SHA-256 + kernel respond) off the ES serial
    // delivery thread so one slow hash cannot serialize every other exec (#298). OperationQueue caps in-flight work at
    // authWorkerConcurrency without spawning a thread per queued item. nonisolated(unsafe): OperationQueue is thread-safe; the
    // annotation only tells Swift 6 this immutable shared reference is intentional.
    nonisolated(unsafe) let authDecisionQueue: OperationQueue = {
        let queue = OperationQueue()
        queue.name = "com.fleetdm.edr.authexec.decision"
        queue.maxConcurrentOperationCount = authWorkerConcurrency
        queue.qualityOfService = .userInitiated
        return queue
    }()

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
            // Launch-item persistence (T1543.004 LaunchDaemons) is detected via BTM registration rather than raw file
            // writes: lower volume, and robust to atomic-rename / `cp` drops a file-write rule misses. See
            // handleBtmLaunchItemAdd (ADR-0008).
            //
            // Broad NOTIFY_OPEN / NOTIFY_CREATE are deliberately NOT subscribed here (#301, ADR-0008): NOTIFY_OPEN cannot
            // be muted per-event-type and was the open/create firehose. Sensitive-path file writes (sudoers) are now
            // watched by the dedicated, target-muted FileTamperSubscriber client, which keeps target-path mute inversion
            // off this exec-authorization client.
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
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
        // Drain in-flight AUTH decisions before deleting the client: each holds a retained message it must still respond to
        // and release, and es_respond on a deleted client is undefined. Operations are deadline-bounded, so this returns
        // promptly (#298).
        authDecisionQueue.waitUntilAllOperationsAreFinished()
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
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            handleBtmLaunchItemAdd(msg)
        default:
            break
        }
    }

    /// AUTH_EXEC handler. Decision order: (1) platform-binary carve-out (#205) ALLOWs Apple system binaries with cache:true to
    /// avoid bricking the host on an admin-applied BINARY rule for launchd/xpcproxy/etc; (2) self-allow failsafe ALLOWs the
    /// agent + extensions + host app uncached (team_id + bundle-id match); (3) decideAuthExec walks CDHASH → BINARY →
    /// CERTIFICATE → SIGNINGID → TEAMID → PATH (Phase B close-out, PR for #210). The platform-binary and self-allow ALLOWs
    /// respond inline (no I/O); everything past them runs on a bounded worker queue off the ES serial delivery thread so a slow
    /// hash cannot serialize other execs (#298). BINARY hashing stays bounded by msg.deadline (#208 close-out); on deadline /
    /// read failure the walk continues through every lower layer first and only applies the snapshot's deadlineFallback posture
    /// when no later rule matches. CERTIFICATE +
    /// SIGNINGID + TEAMID rely on SigningInfoFallback's cached SecCode walk; PATH uses canonicalizePath on the exec target
    /// path so the in-memory comparison matches the server-side persisted canonical form verbatim.
    private func handleAuthExec(_ message: UnsafePointer<es_message_t>) {
        let target = message.pointee.event.exec.target.pointee
        let teamID = esTokenString(target.team_id)
        let signingID = esTokenString(target.signing_id)

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

        // Everything past here may walk SecCode (TeamID / leaf-cert fallback) and stream a SHA-256 over the target — tens of
        // ms on a multi-MB binary — and it currently runs inline on the kernel's single serial AUTH delivery thread. Offload it
        // to a bounded worker so one slow hash cannot serialize (and, once a queued exec burns its deadline, fail-closed DENY)
        // every other exec on the host (#298). Under a saturated backlog, decide inline rather than growing an unbounded queue
        // of retained messages — strictly no worse than the pre-#298 serial path. The decision logic, the deadline budget, and
        // the fail-closed/open posture are all unchanged — only the thread they run on moves.
        if authDecisionQueue.operationCount >= maxAuthDecisionBacklog {
            decideAndRespond(message)
            return
        }
        let retained = RetainedAuthMessage(message)
        authDecisionQueue.addOperation { [self, retained] in
            // retained releases the message in deinit when this operation is freed — after decideAndRespond has responded,
            // exactly once, and even if the operation is ever dropped before running.
            decideAndRespond(retained.message)
        }
    }

    /// decideAndRespond runs the full AUTH_EXEC decision for `message` and responds to the kernel: re-derive the target, walk
    /// the identifier tuple, hash under the deadline budget when BINARY rules exist, decide, and dispatch the verdict +
    /// telemetry. Called on the bounded worker for the offloaded common case, and inline on the ES delivery thread for the
    /// saturated-backlog fallback (#298). `message` must be valid for the call — guaranteed by RetainedAuthMessage on the
    /// worker path and by the live ES callback on the inline path. C structs are re-derived here (not captured): es_process_t /
    /// stat are non-Sendable and their fields point into the message buffer.
    private func decideAndRespond(_ message: UnsafePointer<es_message_t>) {
        let target = message.pointee.event.exec.target.pointee
        let fileStat = target.executable.pointee.stat
        let path = esTokenString(target.executable.pointee.path)

        let snapshot = ApplicationControlStore.shared.currentSnapshot()
        let tuple = buildAuthTuple(target: target, fileStat: fileStat, path: path)

        // Only pay the hash cost when the snapshot actually has BINARY rules to consult. The cheap CDHASH/SIGNINGID/TEAMID
        // layers run unconditionally; the hash compute alone is the latency outlier and is wasted work when no BINARY rule
        // could fire.
        let hashOutcome: HashOutcome
        if snapshot.binaryRules.isEmpty {
            hashOutcome = .notNeeded
        } else {
            hashOutcome = FileHashCache.shared.lookupOrComputeWithDeadline(
                path: path,
                stat: fileStat,
                deadlineMachAbs: message.pointee.deadline
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
            // matchedIdentifier is .private to honor the "no PII in log statements" coding guideline. For BINARY/CDHASH/
            // CERTIFICATE this is a hex digest -- not PII but uniform privacy keeps the log policy simple; for PATH (added
            // in PR #290 for #210) it's an absolute filesystem path that IS PII and MUST stay out of the public log. The
            // full identifier still flows to the server in the application_control_block event payload (where the project
            // guideline explicitly permits file paths). CodeRabbit MAJOR on PR #290.
            logger.warning(
                "AUTH_EXEC DENIED type=\(rule.ruleType, privacy: .public) id=\(matchedIdentifier, privacy: .private)"
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
