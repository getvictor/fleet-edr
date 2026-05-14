import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "NotificationClient")

/// NotificationClient is the extension's outbound channel to the
/// host app's block-notification surface. The decision engine fires
/// `notify(_:)` after returning DENY to the kernel, so the modal
/// pops on the user's desktop without ever blocking the AUTH_EXEC
/// callback.
///
/// File-based transport (demo cut). The extension runs in the
/// system bootstrap namespace; the host app runs in a per-user GUI
/// session. Cross-bootstrap XPC Mach-service lookup requires either
/// a session-bridging helper or `xpc_session_*` APIs (macOS 13+
/// `xpc_connection_create_for_uid`), which is Phase B work. For the
/// demo dry-run we drop a JSON file at a well-known path and the
/// host app's NotificationListener picks it up via FSEvents.
///
/// Wire shape on disk is the same `BlockNotificationPayload` Codable
/// that the XPC path used, so the host app's decoder needs no
/// changes — only the transport.
///
/// Concurrency: a dedicated serial queue keeps writes ordered. The
/// extension is the sole writer; the host app is the sole reader.
final class NotificationClient {
    static let shared = NotificationClient()

    private let queue = DispatchQueue(label: "com.fleetdm.edr.securityextension.notification-client")
    // Encoder is configured once. Sorted keys makes a captured wire
    // sample diffable across runs — useful for the unified-log
    // forensic trail, not for behavior. The host-app side dedups on
    // (rule_id, binary_path), not on byte-identical JSON.
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = .sortedKeys
        return e
    }()

    private init() {}

    /// notify drops a block-notification payload to the file-system
    /// rendezvous the host app watches. Fire-and-forget: the
    /// extension already returned DENY to the kernel, so swallowing
    /// the write error is the safe direction. The host app's
    /// NSAlert is post-hoc UX, not authorization.
    ///
    /// Atomicity is the dance:
    ///   1. Create the drop directory at mode 1777 (sticky) so any
    ///      user-session process can read files but only the file
    ///      owner (root, us) can delete or replace them.
    ///   2. Write the payload to a tempfile under the drop directory.
    ///   3. Rename the tempfile to a UUID-named final path. macOS
    ///      `rename(2)` is atomic on the same filesystem, so the
    ///      host app's FSEvents source never observes a partial
    ///      JSON.
    ///   4. chmod the final file to 0644 so the user-session reader
    ///      can open + read it.
    func notify(_ payload: BlockNotificationPayload) {
        queue.async { [weak self] in
            guard let self else { return }
            guard let data = self.encodePayload(payload) else { return }
            self.ensureDropDirectory()
            let finalURL = URL(fileURLWithPath: "\(blockNotificationDropDir)/\(UUID().uuidString).json")
            let tempURL = finalURL.appendingPathExtension("tmp")
            do {
                try data.write(to: tempURL, options: .atomic)
                try FileManager.default.moveItem(at: tempURL, to: finalURL)
                try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: finalURL.path)
            } catch {
                logger.error("notification drop failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// encodePayload renders the JSON bytes the host app's
    /// JSONDecoder consumes. Failure here is a programmer error
    /// (the payload is a fixed struct with no failable
    /// initializers) — log and bail so the call site doesn't get
    /// noisier handling a case that shouldn't happen.
    private func encodePayload(_ payload: BlockNotificationPayload) -> Data? {
        do {
            return try encoder.encode(payload)
        } catch {
            logger.error("encode block notification: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    /// ensureDropDirectory makes the rendezvous directory exist at
    /// the right permissions. Idempotent — called on every notify
    /// so a manually-deleted directory doesn't break subsequent
    /// blocks. Sticky-bit mode (1777) is the standard pattern for
    /// shared drop directories: anyone can write, only file owners
    /// can delete their own files.
    private func ensureDropDirectory() {
        let url = URL(fileURLWithPath: blockNotificationDropDir)
        // posixPermissions = 0o1777 (sticky + rwx for everyone).
        // The Swift FileAttributeKey API takes the bits as an Int
        // matching `stat.st_mode`'s low bits; the leading 1 is the
        // sticky bit.
        let attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o1777]
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: attrs)
            // createDirectory honors `attributes` only on the
            // leaf when it creates it; if the directory already
            // existed at the wrong perms, force-correct.
            try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path)
        } catch {
            logger.error("notification drop directory init failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
