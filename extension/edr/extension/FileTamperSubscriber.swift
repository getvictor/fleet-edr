import EndpointSecurity
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFFileTamper")

/// FileTamperSubscriber is the DEDICATED, NOTIFY-only second Endpoint Security client that watches a small, fixed set of
/// sensitive target paths for content changes (ADR-0008, #301). It is separate from the primary ESFSubscriber client for one
/// hard ESF reason: target-path mute *inversion* (`es_invert_muting`) is client-global, and `AUTH_EXEC`'s "target" is the
/// executable being launched. Inverting target-path muting to "observe only /etc/sudoers*" on a client that also handles
/// `AUTH_EXEC` would filter exec authorization (and Application Control) by that same path list — breaking enforcement. So the
/// inversion lives here, on a client with NO auth subscriptions (exactly what `es_invert_muting`'s documentation requires),
/// and the primary client keeps unfiltered exec authorization.
///
/// Subscriptions: NOTIFY_CREATE (new sudoers.d drop) and NOTIFY_WRITE (in-place edit / overwrite of an existing sudoers
/// file). Each is re-emitted as an `open` event with synthetic write-mode flags so the server's sudoers_tamper rule consumes
/// them unchanged (the same division of labour handleCreate used before #301). NOTIFY_OPEN is deliberately NOT used: ESF
/// silently ignores per-event-type muting for it, so it cannot be target-scoped and was the open/create firehose #301
/// removes. NOTIFY_RENAME is deliberately NOT subscribed: visudo/sudoedit write via temp-file + atomic rename onto
/// /etc/sudoers, so watching rename would fire on every legitimate sudoers edit; the atomic-replace gap stays documented on
/// the sudoers_tamper rule (unchanged from before #301).
final class FileTamperSubscriber: Sendable {
    // swiftlint:disable:next implicitly_unwrapped_optional
    private nonisolated(unsafe) var client: OpaquePointer!
    private let serializer = EventSerializer()
    nonisolated(unsafe) var onEvent: ((Data) -> Void)?

    /// watchedTargets is the fixed sensitive-path set this client observes after inversion. /etc is a symlink to /private/etc
    /// on macOS and ESF reports the resolved (/private/etc) form, so both spellings are muted defensively. LITERAL pins
    /// /etc/sudoers exactly; PREFIX covers everything under /etc/sudoers.d/. A TARGET_PREFIX matches all descendants sharing
    /// the prefix, so the trailing slash keeps it from also matching siblings like /etc/sudoers.d.bak; the server sudoersPath
    /// regex further narrows to direct children of the directory.
    private static let watchedTargets: [(path: String, type: es_mute_path_type_t)] = [
        ("/private/etc/sudoers", ES_MUTE_PATH_TYPE_TARGET_LITERAL),
        ("/etc/sudoers", ES_MUTE_PATH_TYPE_TARGET_LITERAL),
        ("/private/etc/sudoers.d/", ES_MUTE_PATH_TYPE_TARGET_PREFIX),
        ("/etc/sudoers.d/", ES_MUTE_PATH_TYPE_TARGET_PREFIX)
    ]

    init() {
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
        // A mute failure leaves that target unobserved after inversion (a silent coverage gap), so treat it as fatal —
        // consistent with the invert + subscribe failures below. The watched set is a fixed list of valid absolute paths,
        // so a failure here means a misconfigured client, not a bad path.
        Self.watchedTargets.forEach { target in
            guard es_mute_path(client, target.path, target.type) == ES_RETURN_SUCCESS else {
                logger.error("file-tamper mute failed for \(target.path, privacy: .public)")
                exit(EXIT_FAILURE)
            }
        }
        guard es_invert_muting(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_RETURN_SUCCESS else {
            logger.error("file-tamper target-path mute inversion failed")
            exit(EXIT_FAILURE)
        }

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_WRITE
        ]
        guard es_subscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            logger.error("file-tamper subscribe failed")
            exit(EXIT_FAILURE)
        }
        logger.info("FileTamper client active: target-muted (inverted) to /etc/sudoers* — CREATE/WRITE only")
    }

    func stop() {
        es_unsubscribe_all(client)
        es_delete_client(client)
    }

    private func handleMessage(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        guard let path = Self.targetPath(of: msg) else {
            return
        }
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        // Synthetic write-mode flags (O_WRONLY|O_CREAT|O_TRUNC): the inverted target muting already scoped this client to
        // content-modifying events on sensitive paths, and the server's sudoers_tamper rule gates on the access-mode bits.
        // Reusing the `open` event type keeps the wire format + the rule unchanged.
        let payload = OpenPayload(pid: pid, path: path, flags: Int(O_WRONLY | O_CREAT | O_TRUNC))
        if let data = serializer.serialize(eventType: "open", payload: payload) {
            // path is .private: exec/file paths can carry usernames or project tokens, and the "no PII in logs" guideline
            // applies on this hot path. The full path still flows to the server in the event payload for the rule.
            logger.debug("file-tamper type=\(msg.event_type.rawValue, privacy: .public) pid=\(pid, privacy: .public) path=\(path, privacy: .private)")
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
