import EndpointSecurity
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFFileTamper")

/// FileTamperSubscriber is the DEDICATED, NOTIFY-only second Endpoint Security client that watches a small set of sensitive
/// target paths for content changes (ADR-0008, #301). The set is the built-in sudoers paths plus whatever the server
/// pushes (ADR-0008 step 4, #998), and a pushed set is applied to the running client without a restart.
///
/// It is separate from the primary ESFSubscriber client for one hard ESF reason: target-path mute *inversion*
/// (`es_invert_muting`) is client-global, and `AUTH_EXEC`'s "target" is the executable being launched. Inverting target-path
/// muting to "observe only the watched paths" on a client that also handles `AUTH_EXEC` would filter exec authorization (and
/// Application Control) by that same path list, breaking enforcement. So the inversion lives here, on a client with NO auth
/// subscriptions (exactly what `es_invert_muting`'s documentation requires), and the primary client keeps unfiltered exec
/// authorization.
///
/// Subscriptions: NOTIFY_CREATE (new sudoers.d drop) and NOTIFY_WRITE (in-place edit / overwrite of an existing sudoers
/// file). Each is re-emitted as an `open` event with synthetic write-mode flags so the server's sudoers_tamper rule consumes
/// them unchanged (the same division of labour handleCreate used before #301).
///
/// NOTIFY_RENAME is subscribed as of #917, and emitted as its own `file_rename` event carrying both paths. It was previously
/// declined on the grounds that watching rename would fire on every legitimate visudo edit. That reasoning did not hold, and
/// measurement on macOS 26.3 is what settled it: one `visudo -f /etc/sudoers.d/<name>` already produces CREATE, WRITE and
/// UNLINK on `<name>.tmp`, a SIBLING inside the watched `/etc/sudoers.d/` prefix, so the visudo traffic this client sees
/// exists with or without rename (it was firing the rule; see #933). What rename adds is the only event carrying a source
/// path, which is what finally lets the server tell a promotion into live policy from a move that changes nothing.
///
/// NOTIFY_OPEN, NOTIFY_TRUNCATE and NOTIFY_UNLINK are subscribed as of #934, for destruction of sudo policy: emptying a
/// sudoers file or removing one produced no telemetry at all before. NOTIFY_OPEN is the awkward one, and it is here because
/// `: > /etc/sudoers` empties the file through open(2) with O_TRUNC, a different kernel path from truncate(2) that raises no
/// CREATE, WRITE, TRUNCATE, RENAME or UNLINK. Opens without O_TRUNC are discarded in handleOpen before reaching the wire, so
/// routine reads of the policy (every `sudo` invocation makes one) are not reported.
///
/// The reason NOTIFY_OPEN was avoided until then was wrong, and is worth not repeating: the claim was that ESF ignores muting
/// for it. Measured with THIS client's configuration on 26.3, target-path mute inversion is honoured for NOTIFY_OPEN, with
/// zero events across two seconds of unrelated filesystem traffic.
final class FileTamperSubscriber: Sendable {
    // swiftlint:disable:next implicitly_unwrapped_optional
    private nonisolated(unsafe) var client: OpaquePointer!
    private let serializer = EventSerializer()
    nonisolated(unsafe) var onEvent: ((Data) -> Void)?

    /// applyQueue serializes every change to the muted set, so a pushed set arriving over XPC and the startup configuration
    /// cannot interleave their mute calls. `applied` and `pushed` are only read and written on it.
    private let applyQueue = DispatchQueue(label: "com.fleetdm.edr.filetamper.watched-paths")
    /// applied is the target set currently muted, and therefore observed once inversion is on (WatchedPaths.targets).
    private nonisolated(unsafe) var applied: [WatchedPath] = []
    /// pushed is the latest server-pushed set. One that arrives before start() is held here and applied when the client starts.
    private nonisolated(unsafe) var pushed: [WatchedPath]
    private nonisolated(unsafe) var started = false

    /// pushed is the set persisted by the last push (WatchedPathStore), applied with the built-in paths when the client starts.
    init(pushed: [WatchedPath]) {
        self.pushed = pushed
        var rawClient: OpaquePointer?
        let result = es_new_client(&rawClient) { [weak self] _, message in
            self?.handleMessage(message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let rawClient else {
            logger.error("Failed to create file-tamper ES client: \(result.rawValue)")
            exit(EXIT_FAILURE)
        }
        self.client = rawClient
    }

    func start() {
        // Configure muting + inversion BEFORE subscribing so there is never a window where this client sees the unscoped
        // create/write firehose. es_unmute_all_target_paths clears the default target-path mute set first (the SDK's
        // documented prerequisite for inverting target-path muting); then mute the watched paths; then invert so the muted
        // set becomes the ONLY observed set.
        es_unmute_all_target_paths(client)
        applyQueue.sync {
            reconcile()
            started = true
        }
        guard es_invert_muting(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_RETURN_SUCCESS else {
            logger.error("file-tamper target-path mute inversion failed")
            exit(EXIT_FAILURE)
        }

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_TRUNCATE,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            // NOTIFY_OPEN is the noisy one, and it is here because the common way to destroy a sudoers file emits nothing
            // else. `: > /etc/sudoers` empties the file through open(2) with O_TRUNC, which is a different kernel path from
            // truncate(2) and raises no CREATE, WRITE, TRUNCATE, RENAME or UNLINK. Measured on macOS 26.3: three separate
            // O_TRUNC paths (bash, sh, python) each took a 37-byte file to zero and produced ZERO events, while
            // `truncate -s 0` produced one.
            //
            // Every open that is not destructive is discarded in handleOpen before it can reach the wire, so what this
            // subscription costs is a callback per open of a sudoers path, not a stream of events. On this host that is a
            // handful per `sudo` invocation.
            ES_EVENT_TYPE_NOTIFY_OPEN
        ]
        guard es_subscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            logger.error("file-tamper subscribe failed")
            exit(EXIT_FAILURE)
        }
        let summary = "FileTamper client active: target-muted (inverted) to \(appliedCount) watched targets: " +
            "CREATE/WRITE/RENAME/TRUNCATE/UNLINK/OPEN"
        logger.info("\(summary, privacy: .public)")
    }

    private var appliedCount: Int {
        applyQueue.sync { applied.count }
    }

    /// apply makes a pushed set the watched set on the running client. The built-in paths stay watched whatever is pushed, and a path
    /// in both the old and the new set is never unmuted, so replacing the set opens no gap in what was already covered.
    func apply(pushed next: [WatchedPath]) {
        applyQueue.async {
            self.pushed = next
            if self.started {
                self.reconcile()
            }
        }
    }

    /// reconcile mutes and unmutes the difference between the applied targets and those the current pushed set calls for. Runs on
    /// applyQueue.
    ///
    /// Mutes come first and unmutes only follow when every mute succeeded. A mute that fails leaves the client watching everything it
    /// watched before this update, the paths the update drops included, rather than dropping them while the paths meant to replace
    /// them are missing; the failed target is not recorded as applied, so the next update tries it again.
    ///
    /// A built-in path that fails to mute is fatal, as it was when the set was fixed: after inversion that path would silently go
    /// unobserved, and the shipped sudoers rules would go blind with it. A pushed path that fails is logged instead, because the set
    /// persists, and exiting on it would restart the extension into the same failure on every launch.
    private func reconcile() {
        let next = WatchedPaths.targets(pushed: pushed)
        let builtIn = Set(WatchedPaths.targets(pushed: []))
        let (mute, unmute) = WatchedPaths.changes(from: applied, to: next)
        var muted = 0
        var failedMutes = 0
        for target in mute {
            guard es_mute_path(client, target.path, Self.muteType(target.match)) == ES_RETURN_SUCCESS else {
                logger.error("file-tamper mute failed for \(target.path, privacy: .public)")
                if builtIn.contains(target) {
                    exit(EXIT_FAILURE)
                }
                failedMutes += 1
                continue
            }
            applied.append(target)
            muted += 1
        }
        var unmuted = 0
        if failedMutes == 0 {
            for target in unmute {
                guard es_unmute_path(client, target.path, Self.muteType(target.match)) == ES_RETURN_SUCCESS else {
                    // Still muted, so still observed: it stays in the applied set, and the next update tries again.
                    logger.error("file-tamper unmute failed for \(target.path, privacy: .public)")
                    continue
                }
                applied.removeAll { $0 == target }
                unmuted += 1
            }
        }
        let summary = "file-tamper watched targets: \(applied.count) (+\(muted) -\(unmuted), \(failedMutes) failed" +
            (failedMutes > 0 ? ", nothing unmuted)" : ")")
        logger.info("\(summary, privacy: .public)")
    }

    private static func muteType(_ match: WatchedPathMatch) -> es_mute_path_type_t {
        switch match {
        case .literal:
            return ES_MUTE_PATH_TYPE_TARGET_LITERAL
        case .prefix:
            return ES_MUTE_PATH_TYPE_TARGET_PREFIX
        }
    }

    func stop() {
        es_unsubscribe_all(client)
        es_delete_client(client)
    }

    private func handleMessage(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            handleRename(msg)
            return
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            emitDestruction(msg, eventType: "file_truncate", path: esTokenString(msg.event.truncate.target.pointee.path))
            return
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            emitDestruction(msg, eventType: "file_delete", path: esTokenString(msg.event.unlink.target.pointee.path))
            return
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            handleOpen(msg)
            return
        default:
            break
        }
        guard let path = Self.targetPath(of: msg) else {
            return
        }
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        // Synthetic write-mode flags (O_WRONLY|O_CREAT|O_TRUNC): the inverted target muting already scoped this client to
        // content-modifying events on sensitive paths, and the server's sudoers_tamper rule gates on the access-mode bits.
        // Reusing the `open` event type keeps the wire format + the rule unchanged.
        let payload = OpenPayload(pid: pid, path: path, flags: Int(O_WRONLY | O_CREAT | O_TRUNC))
        if let data = serializer.serialize(eventType: "open", payload: payload, kernelTimeNs: kernelEventTimeNs(msg.time)) {
            // path is .private: exec/file paths can carry usernames or project tokens, and the "no PII in logs" guideline
            // applies on this hot path. The full path still flows to the server in the event payload for the rule.
            logger.debug("file-tamper type=\(msg.event_type.rawValue, privacy: .public) pid=\(pid, privacy: .public) path=\(path, privacy: .private)")
            onEvent?(data)
        }
    }

    /// handleRename emits a `file_rename` event for a rename where EITHER path falls in the watched set, which is what the
    /// inverted target-path muting delivers (measured on macOS 26.3: a rename into, within, and out of the set all arrive).
    ///
    /// Renames are emitted whole, both paths, and the server decides. The extension does not try to tell a legitimate editor
    /// commit from an attacker's promotion, because it cannot: the discriminator is whether the DESTINATION is a name sudo
    /// will parse, and that is policy knowledge (`sudoers(5)`'s dot and tilde skipping) which belongs with the rule, not in
    /// the hot path of an ESF callback.
    private func handleRename(_ msg: es_message_t) {
        let rename = msg.event.rename
        let source = esTokenString(rename.source.pointee.path)
        let destination: String
        switch rename.destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            destination = Self.joinDir(rename.destination.new_path.dir, rename.destination.new_path.filename)
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            destination = esTokenString(rename.destination.existing_file.pointee.path)
        default:
            return
        }
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        let payload = FileRenamePayload(pid: pid, sourcePath: source, path: destination)
        if let data = serializer.serialize(eventType: "file_rename", payload: payload, kernelTimeNs: kernelEventTimeNs(msg.time)) {
            // Both paths are .private for the same reason the CREATE/WRITE path's is: a file path can carry a username or a
            // project token, and the full values still reach the server in the payload.
            logger.debug("file-tamper rename pid=\(pid, privacy: .public) src=\(source, privacy: .private) dst=\(destination, privacy: .private)")
            onEvent?(data)
        }
    }

    /// oTrunc is the O_TRUNC bit as it appears in an ESF open event's fflag.
    ///
    /// Named and measured rather than taken from <fcntl.h>, because ESF reports the kernel's internal fflags rather than the
    /// flags the caller passed to open(2), and the two conventions do not agree on every bit. Measured on macOS 26.3: a
    /// `: > file` redirect arrives as fflag=1026, which has this bit set, and sudo's own routine reads of /etc/sudoers arrive
    /// as fflag=5, which does not. That one bit is the whole filter.
    ///
    /// Typed Int32 to match `es_event_open_t.fflag` as Swift imports it. Not cosmetic: `swift build` does not catch a mismatch
    /// here, because this file imports EndpointSecurity and is excluded from the SwiftPM target, so only xcodebuild or an ESF
    /// harness compiles it.
    private static let oTrunc: Int32 = 0x0000_0400

    /// handleOpen discards every open that is not destructive, and emits the rest as a truncation.
    ///
    /// The discard is the point. Subscribing NOTIFY_OPEN is what makes `: > /etc/sudoers` visible at all, and it is also what
    /// would put every read of a sudoers file on the wire: `sudo` opens /etc/sudoers on each invocation, so an unfiltered
    /// subscription would report routine privilege checks as file activity. Testing one bit here keeps the wire carrying only
    /// opens that discarded the file's contents.
    private func handleOpen(_ msg: es_message_t) {
        guard msg.event.open.fflag & Self.oTrunc != 0 else {
            return
        }
        emitDestruction(msg, eventType: "file_truncate", path: esTokenString(msg.event.open.file.pointee.path))
    }

    /// emitDestruction serializes a truncation or a deletion, which share a payload shape and differ only in what they mean.
    private func emitDestruction(_ msg: es_message_t, eventType: String, path: String) {
        guard !path.isEmpty else {
            return
        }
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        let data: Data?
        if eventType == "file_delete" {
            data = serializer.serialize(eventType: eventType, payload: FileDeletePayload(pid: pid, path: path),
                                        kernelTimeNs: kernelEventTimeNs(msg.time))
        } else {
            data = serializer.serialize(eventType: eventType, payload: FileTruncatePayload(pid: pid, path: path),
                                        kernelTimeNs: kernelEventTimeNs(msg.time))
        }
        if let data {
            // path is .private for the same reason every other handler here marks it so: a file path can carry a username or
            // a project token, and the full value still reaches the server in the payload.
            logger.debug("file-tamper \(eventType, privacy: .public) pid=\(pid, privacy: .public) path=\(path, privacy: .private)")
            onEvent?(data)
        }
    }

    /// targetPath returns the file path a CREATE/WRITE event acts on (the destination for create), or nil for an event shape
    /// we don't map. The create destination union is read per destination_type; the NEW_PATH dir+filename join is via joinDir.
    private static func targetPath(of msg: es_message_t) -> String? {
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            return esTokenString(msg.event.write.target.pointee.path)
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            let create = msg.event.create
            switch create.destination_type {
            case ES_DESTINATION_TYPE_NEW_PATH:
                return joinDir(create.destination.new_path.dir, create.destination.new_path.filename)
            case ES_DESTINATION_TYPE_EXISTING_FILE:
                return esTokenString(create.destination.existing_file.pointee.path)
            default:
                return nil
            }
        default:
            return nil
        }
    }

    /// joinDir joins a NEW_PATH destination's parent directory and filename into an absolute path.
    private static func joinDir(_ dir: UnsafeMutablePointer<es_file_t>, _ filename: es_string_token_t) -> String {
        let parent = esTokenString(dir.pointee.path)
        let name = esTokenString(filename)
        return parent.hasSuffix("/") ? parent + name : parent + "/" + name
    }
}
