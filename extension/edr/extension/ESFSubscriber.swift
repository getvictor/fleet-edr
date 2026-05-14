import EndpointSecurity
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFSubscriber")

/// Our Apple Developer Team ID. Any binary signed with this team_id is
/// allowed through AUTH_EXEC regardless of rule match — the failsafe that
/// prevents a misconfigured rule from blocking the agent, extension, or
/// host app itself. Hardcoded for the application-control demo cut; Phase B
/// of the broader change replaces this with a server-pushed failsafe list
/// so operators can extend it without an agent re-release.
private let extensionTeamID = "FDG8Q7N4CC"

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
        // Application Control demo cut: AUTH_EXEC consults the
        // ApplicationControlStore snapshot and denies BINARY-matched execs.
        // Cache misses on the lazy file-hash cache return ALLOW silently;
        // the cache fills off the callback so the next exec of the same
        // binary catches. See FileHashCache + ApplicationControlStore.
        logger.info("Application Control active: AUTH_EXEC consults BINARY rule snapshot")
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
    /// The demo cut enforces only the BINARY rule type. Walk:
    ///   1. Failsafe — if the exec target's `team_id` is our own, ALLOW.
    ///      Prevents a misconfigured rule from blocking the agent /
    ///      extension / host app. The Phase B server-pushed failsafe list
    ///      will widen this to include platform binaries (`launchd`,
    ///      `systemextensionsd`, etc.) and additional admin-defined
    ///      carve-outs.
    ///   2. Lazy file SHA-256 cache lookup by `(dev, inode, mtime)`. Cache
    ///      misses do NOT block the AUTH callback — the BINARY rule type
    ///      silently misses for this exec, the cache fills off-thread,
    ///      and the next exec of the same binary catches. This is the
    ///      "first launch allowed, second launch blocked" behavior the
    ///      demo plan documents and the recording exercises.
    ///   3. Snapshot lookup — if the cached hash matches a BINARY rule
    ///      with `action=BLOCK` and `enforcement=PROTECT`, DENY.
    ///      Otherwise ALLOW.
    ///
    /// The decision is reached inside the AUTH_EXEC deadline because every
    /// step is a constant-time map lookup; signing-info fetch + file read
    /// happen on the lazy-fill background path, never on the callback.
    private func handleAuthExec(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let target = msg.event.exec.target.pointee
        // esTokenString uses the token's explicit length; es_string_token_t
        // is NOT NUL-guaranteed and String(cString:) can overread.
        let path = esTokenString(target.executable.pointee.path)
        let teamID = esTokenString(target.team_id)
        let fileStat = target.executable.pointee.stat

        // Failsafe carve-out.
        if teamID == extensionTeamID {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let snapshot = ApplicationControlStore.shared.currentSnapshot()
        if let sha256 = FileHashCache.shared.lookup(stat: fileStat) {
            if let rule = snapshot.binaryRules[sha256],
               rule.action == ApplicationControlAction.block,
               rule.enforcement == ApplicationControlEnforcement.protect {
                logger.warning("AUTH_EXEC DENIED by application control: \(path, privacy: .public) sha256=\(sha256, privacy: .public)")
                es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
                return
            }
        } else {
            // Cache miss: kick the async fill so the next exec of this
            // binary hits the cache. Documented behavior — never block
            // the AUTH callback on a file read.
            FileHashCache.shared.startLazyFill(path: path, stat: fileStat)
        }
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
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

        let payload = ExecPayload(
            pid: pid,
            ppid: ppid,
            path: path,
            args: args,
            cwd: "", // es_process_t has no cwd member on macOS 26 SDK
            uid: uid,
            gid: gid,
            codeSigning: codeSigning,
            sha256: sha256
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
