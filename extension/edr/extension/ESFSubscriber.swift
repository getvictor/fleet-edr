import EndpointSecurity
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFSubscriber")

// Phase 2: the blocklist is now a runtime set owned by PolicyStore.shared. The server
// pushes updates over the agent's XPC connection; the extension persists them to
// /var/db/com.fleetdm.edr/policy.json and swaps the in-memory set atomically. The
// hardcoded demo list (`/tmp/payload-block`) is gone; operators configure equivalents
// via `PUT /api/v1/admin/policy` on the server.

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

    /// AUTH_EXEC handler: check the target binary against the runtime blocklist and
    /// respond with DENY or ALLOW. The lookup is O(log n) through Set's hashing, well
    /// within the kernel's AUTH deadline. For denied execs the kernel returns EPERM to
    /// the caller and the binary never runs. The blocklist is owned by PolicyStore —
    /// server-driven policy pushes swap it atomically.
    private func handleAuthExec(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let target = msg.event.exec.target.pointee
        let path = String(cString: target.executable.pointee.path.data)

        if PolicyStore.shared.currentBlockedPaths().contains(path) {
            logger.warning("AUTH_EXEC DENIED: \(path, privacy: .public)")
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
        } else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
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

        let codeSigning = extractCodeSigning(from: target)

        let payload = ExecPayload(
            pid: pid,
            ppid: ppid,
            path: path,
            args: args,
            cwd: "", // es_process_t has no cwd member on macOS 26 SDK
            uid: uid,
            gid: gid,
            codeSigning: codeSigning,
            sha256: nil
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
