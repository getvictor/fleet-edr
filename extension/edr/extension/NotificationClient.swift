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
/// changes - only the transport.
///
/// Concurrency: a dedicated serial queue keeps writes ordered. The
/// extension is the sole writer; the host app is the sole reader.
final class NotificationClient {
    static let shared = NotificationClient()

    private let queue = DispatchQueue(label: "com.fleetdm.edr.securityextension.notification-client")
    // Encoder is configured once. Sorted keys makes a captured wire
    // sample diffable across runs - useful for the unified-log
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
    /// Sequence:
    ///   1. Ensure the drop directory exists with the correct
    ///      ownership (root) and mode (1777). If a non-root principal
    ///      created it first, repair via chown + chmod - we run as
    ///      root and have the authority to do so.
    ///   2. Encode the payload + write to a tempfile.
    ///   3. chmod the tempfile to 0644 BEFORE the rename, so the
    ///      moment the destination path appears it already has the
    ///      readable mode. If we chmod'd after the move, the host
    ///      app's FSEvents source could observe the new file before
    ///      the chmod and fail to read it (permission denied).
    ///   4. atomically rename tempfile → final UUID.json. macOS
    ///      `rename(2)` is atomic on the same filesystem, so the
    ///      host app's FSEvents source never observes a partial
    ///      JSON.
    ///   5. Purge our own old files (> blockNotificationPurgeWindow)
    ///      so the directory stays bounded across many denials.
    func notify(_ payload: BlockNotificationPayload) {
        queue.async { [weak self] in
            guard let self else { return }
            guard let data = self.encodePayload(payload) else { return }
            self.ensureDropDirectory()
            let finalURL = URL(fileURLWithPath: "\(blockNotificationDropDir)/\(UUID().uuidString).json")
            let tempURL = finalURL.appendingPathExtension("tmp")
            do {
                try data.write(to: tempURL, options: .atomic)
                // chmod the tempfile to 0644 BEFORE the rename. After
                // the rename the host app's FSEvents source can
                // observe the new path immediately; if the chmod
                // landed after, there's a window where the file is
                // visible at 0600 (the umask default) and the user-
                // session reader gets EACCES.
                try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: tempURL.path)
                try FileManager.default.moveItem(at: tempURL, to: finalURL)
            } catch {
                logger.error("notification drop failed: \(error.localizedDescription, privacy: .public)")
            }
            self.purgeStaleDrops()
        }
    }

    /// encodePayload renders the JSON bytes the host app's
    /// JSONDecoder consumes. Failure here is a programmer error
    /// (the payload is a fixed struct with no failable
    /// initializers) - log and bail so the call site doesn't get
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
    /// the right ownership AND permissions. Idempotent - called on
    /// every notify so a manually-deleted or maliciously-recreated
    /// directory doesn't break subsequent blocks.
    ///
    /// Sticky-bit mode (1777) is the standard pattern for shared
    /// drop directories: anyone can write, only file owners can
    /// delete their own files. But createDirectory(attributes:)
    /// only applies the requested mode on CREATE; if the directory
    /// already existed (e.g. a non-root local user pre-created it
    /// to lower the mode + race the bootstrap), the attributes
    /// argument is silently ignored. So we force-correct ownership
    /// AND mode after the createDirectory call, using chown(2) and
    /// chmod(2) directly so they fire whether the dir is fresh or
    /// pre-existing. We're root, so both syscalls succeed.
    private func ensureDropDirectory() {
        let url = URL(fileURLWithPath: blockNotificationDropDir)
        let attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o1777]
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: attrs)
        } catch {
            logger.error("notification drop directory init failed: \(error.localizedDescription, privacy: .public)")
            return
        }
        // Force-correct ownership to root:wheel. If a hostile local
        // user pre-created the dir under their own UID, the previous
        // createDirectory call was a no-op (the path already existed)
        // and we'd otherwise keep writing into a user-owned dir.
        if chown(blockNotificationDropDir, 0, 0) != 0 {
            let err = String(cString: strerror(errno))
            logger.error("notification drop directory chown failed: \(err, privacy: .public)")
        }
        // Force-correct mode to sticky 1777 in case the dir
        // pre-existed with looser/tighter perms.
        if chmod(blockNotificationDropDir, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO) != 0 {
            let err = String(cString: strerror(errno))
            logger.error("notification drop directory chmod failed: \(err, privacy: .public)")
        }
    }

    /// purgeStaleDrops unlinks our own .json files older than
    /// blockNotificationPurgeWindow. Bounds the directory size so a
    /// fleet of denied execs doesn't fill /private/tmp indefinitely.
    /// Only touches root-owned files so we don't unlink anything a
    /// local user (legitimately or otherwise) left in this sticky
    /// 1777 dir; the host app's per-file root-uid check already
    /// rejects those for forensic purposes, so leaving them on disk
    /// is the safer direction.
    private func purgeStaleDrops() {
        let url = URL(fileURLWithPath: blockNotificationDropDir)
        let entries: [URL]
        do {
            entries = try FileManager.default.contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles],
            )
        } catch {
            // The dir was just (re)created in ensureDropDirectory;
            // a failure here is unusual. Log + bail so the next
            // notify retries.
            logger.error("notification drop purge enumerate failed: \(error.localizedDescription, privacy: .public)")
            return
        }
        let cutoff = Date().addingTimeInterval(-blockNotificationPurgeWindow)
        for entry in entries where entry.pathExtension == "json" {
            var entrySt = stat()
            if lstat(entry.path, &entrySt) != 0 { continue }
            // Skip non-root files; they're someone else's problem
            // and intentionally preserved for forensics.
            if entrySt.st_uid != 0 { continue }
            // st_mtimespec is the most recent content change. Files
            // older than the cutoff are safe to unlink: the host app
            // had blockNotificationPurgeWindow (5 min) to pick them
            // up, and FSEvents converges in under a second under
            // normal load.
            let mtime = Date(timeIntervalSince1970: TimeInterval(entrySt.st_mtimespec.tv_sec))
            if mtime < cutoff {
                if unlink(entry.path) != 0 {
                    let err = String(cString: strerror(errno))
                    logger.error("notification purge unlink \(entry.lastPathComponent, privacy: .public): \(err, privacy: .public)")
                }
            }
        }
    }
}
