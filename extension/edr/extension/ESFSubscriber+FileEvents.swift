import EndpointSecurity
import Foundation
import os.log

// File-event handlers split out of ESFSubscriber.swift to keep that file under SwiftLint's file_length /
// type_body_length caps (same rationale as the CDHashHex.swift split). They run in the ES message-handler context and
// reach ESFSubscriber's module-internal `serializer` + `onEvent`; `serializer` is declared internal (not private) for
// this reason.
private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFFileEvents")

extension ESFSubscriber {
    func handleOpen(_ msg: es_message_t) {
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        let path = String(cString: msg.event.open.file.pointee.path.data)
        let flags = msg.event.open.fflag

        let payload = OpenPayload(pid: pid, path: path, flags: Int(flags))

        if let data = serializer.serialize(eventType: "open", payload: payload) {
            logger.debug("open pid=\(pid) path=\(path)")
            onEvent?(data)
        }
    }

    /// handleCreate surfaces file creation. ES delivers NOTIFY_CREATE (not NOTIFY_OPEN) when a process creates a NEW
    /// file, so write-to-sensitive-path rules keyed on `open` events (privilege_launchd_plist_write, sudoers_tamper)
    /// miss the canonical "drop a new file" attack without it. We re-emit it as an `open` event with synthetic
    /// write-mode flags so those rules fire unchanged and the server keeps the path filtering -- the same division of
    /// labour as handleOpen (the extension forwards everything; the rules decide). NOTIFY_CREATE is high-volume like
    /// NOTIFY_OPEN; extension-side es_mute_path muting for both is tracked as a follow-up (#301).
    func handleCreate(_ msg: es_message_t) {
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        let create = msg.event.create
        let path: String
        switch create.destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            // New file: ES reports the parent directory and the new filename separately; join them.
            let dir = String(cString: create.destination.new_path.dir.pointee.path.data)
            let filename = esTokenString(create.destination.new_path.filename)
            path = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            // Pre-existing file clobbered via O_CREAT; ES resolves the full path directly.
            path = String(cString: create.destination.existing_file.pointee.path.data)
        default:
            return
        }

        // Synthetic write-mode flags (O_WRONLY|O_CREAT|O_TRUNC): a create is a write, and the `open` consumers key on
        // the access-mode bits. Reusing the `open` event type means no server-side or wire-format change.
        let payload = OpenPayload(pid: pid, path: path, flags: Int(O_WRONLY | O_CREAT | O_TRUNC))

        if let data = serializer.serialize(eventType: "open", payload: payload) {
            logger.debug("create pid=\(pid) path=\(path)")
            onEvent?(data)
        }
    }
}
