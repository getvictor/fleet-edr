import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr", category: "NotificationListener")

/// NotificationListener is the host-app's inbound surface for block
/// notifications the extension drops on AUTH_EXEC denial. The
/// production-target transport is XPC against the Mach service the
/// LaunchAgent registers; the demo cut uses a file-system rendezvous
/// (blockNotificationDropDir) because daemon → user-session XPC
/// needs session-bridging plumbing out of scope for the demo.
///
/// Transport: FSEvents-watch the drop directory. On every change,
/// list the directory, decode every *.json file we haven't already
/// processed, and forward the payload to the BlockAlertPresenter.
/// We track processed UUIDs in memory so a host-app restart re-shows
/// any pending alerts (the user might have missed them while the
/// process was down) but a long-running session doesn't re-fire
/// the same modal.
///
/// Trust model: the sticky-bit (1777) drop directory lets ANY local
/// UID create a UUID-named .json. Sticky bit only blocks cross-user
/// unlink, not creation. Without per-file peer validation a non-root
/// user could forge a BlockNotificationPayload and trigger an NSAlert
/// that looks like it came from the system extension. So:
///   1. start() refuses to bind the watcher unless the drop dir
///      itself is root-owned at mode 1777, proving the extension
///      (not a hostile process) created it.
///   2. scan() rejects any .json whose file owner isn't root, so
///      forgeries from non-root local UIDs never reach the presenter.
/// This mirrors the team-ID code-signing requirement the XPC path
/// enforced via xpc_connection_set_peer_code_signing_requirement.
///
/// Cleanup: the extension owns the dropped files (root-owned, mode
/// 0644) and purges its own files older than
/// blockNotificationPurgeWindow on every notify, so the directory
/// stays bounded. scan() prunes its processed set to UUIDs still on
/// disk so the in-memory bookkeeping tracks the on-disk reality.
final class NotificationListener {
    private let dropDir: String
    private let presenter: BlockAlertPresenter
    private let queue = DispatchQueue(label: "com.fleetdm.edr.notification-listener")
    private var source: DispatchSourceFileSystemObject?
    private var fd: Int32 = -1
    // processed records the UUIDs we've already presented to avoid
    // double-firing if FSEvents fires repeatedly for the same write
    // (which the docs say can happen on rename / chmod sequences).
    // Bounded by scan() against the on-disk set so a long-running
    // host-app session doesn't accumulate stale UUIDs.
    private var processed: Set<String> = []

    init(dropDir: String = blockNotificationDropDir, presenter: BlockAlertPresenter) {
        self.dropDir = dropDir
        self.presenter = presenter
    }

    func start() {
        guard verifyDropDirectory() else { return }
        // O_NOFOLLOW: refuse to open if the final path segment is a
        // symlink (closes the symlink-redirect attack a local user
        // could mount by replacing the rendezvous with a link to
        // somewhere they control).
        // O_DIRECTORY: refuse to open if the target isn't a directory
        // (belt + suspenders with verifyDropDirectory's S_IFDIR check;
        // closes the TOCTOU window between lstat and open).
        let descriptor = open(dropDir, O_EVTONLY | O_NOFOLLOW | O_DIRECTORY)
        if descriptor < 0 {
            // Errno is set; render it so the operator can tell
            // "permission denied" from "doesn't exist" without
            // needing dtruss.
            let err = String(cString: strerror(errno))
            logger.error("notification drop dir open failed: \(err, privacy: .public) path=\(self.dropDir, privacy: .public)")
            return
        }
        fd = descriptor
        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor,
            // .write fires on every directory mutation (rename in,
            // unlink, etc.). .attrib catches the chmod the extension
            // does post-write so even if the rename + chmod look
            // like two separate events we don't miss the second.
            eventMask: [.write, .attrib],
            queue: queue,
        )
        src.setEventHandler { [weak self] in self?.scan() }
        src.setCancelHandler { [weak self] in
            if let descriptor = self?.fd, descriptor >= 0 {
                close(descriptor)
                self?.fd = -1
            }
        }
        src.resume()
        source = src
        logger.info("notification listener watching \(self.dropDir, privacy: .public)")
        // Drain anything already in the drop dir at startup so a
        // host-app restart catches pending notifications the
        // extension dropped while we were down.
        queue.async { [weak self] in self?.scan() }
    }

    /// verifyDropDirectory refuses to start the watcher unless the
    /// drop directory exists with the expected ownership and mode.
    /// The host app does NOT create the directory itself — the
    /// extension (running as root) is the canonical creator. If we
    /// created the dir from a user session, a local non-root user
    /// could win the bootstrap race and we'd silently start reading
    /// notifications from a user-controlled directory. Returning
    /// false aborts start() and leaves a loud log line; the
    /// extension's next AUTH_EXEC denial creates the directory and a
    /// host-app restart resumes the watch.
    private func verifyDropDirectory() -> Bool {
        var st = stat()
        if lstat(dropDir, &st) != 0 {
            let err = String(cString: strerror(errno))
            // "no such file" is normal during a cold start before any
            // AUTH_EXEC denial; the extension creates the dir on its
            // first notify and a subsequent host-app restart picks
            // up the watch.
            logger.info("notification drop dir not ready: \(err, privacy: .public) path=\(self.dropDir, privacy: .public)")
            return false
        }
        if (st.st_mode & S_IFMT) != S_IFDIR {
            logger.error("notification drop dir not a directory path=\(self.dropDir, privacy: .public)")
            return false
        }
        // Drop files are root-written; the directory must be
        // root-owned so a non-root local user can't have created it
        // first and hijacked the rendezvous.
        if st.st_uid != 0 {
            logger.error("notification drop dir not root-owned uid=\(st.st_uid, privacy: .public) path=\(self.dropDir, privacy: .public)")
            return false
        }
        // Sticky-bit 1777 is the only acceptable mode: root + every
        // other UID needs rwx (the host app runs as the logged-in
        // user and must be able to read), and sticky blocks
        // cross-user unlink. A different mode means another
        // principal touched the dir; refuse to bind.
        let permBits = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO | S_ISVTX | S_ISGID | S_ISUID)
        let expected: mode_t = S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO
        if permBits != expected {
            logger.error("notification drop dir wrong mode actual=\(permBits, privacy: .public) want=1777 path=\(self.dropDir, privacy: .public)")
            return false
        }
        return true
    }

    /// scan walks the drop directory, decodes every *.json file we
    /// haven't seen, and forwards the payload to the presenter.
    /// Called on `queue`; FSEvents may coalesce multiple writes so
    /// the loop is the unit of consistency, not each event.
    private func scan() {
        let url = URL(fileURLWithPath: dropDir)
        let entries: [URL]
        do {
            entries = try FileManager.default.contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles],
            )
        } catch {
            logger.error("notification scan: \(error.localizedDescription, privacy: .public)")
            return
        }
        let decoder = JSONDecoder()
        // stillOnDisk tracks every UUID we observed this pass so the
        // processed set can be bounded to "currently-present drops"
        // at the end. The extension purges its own files older than
        // blockNotificationPurgeWindow, so this trims the in-memory
        // bookkeeping to match the on-disk reality.
        var stillOnDisk: Set<String> = []
        for entry in entries where entry.pathExtension == "json" {
            let uuid = entry.deletingPathExtension().lastPathComponent
            stillOnDisk.insert(uuid)
            if processed.contains(uuid) { continue }
            // Per-file peer check: the file MUST be root-owned. A
            // non-root local user could create a UUID.json in the
            // sticky 1777 drop dir; sticky-bit only prevents
            // cross-user unlink, not creation. Rejecting any
            // non-root file here is the only thing preventing a
            // forged BlockNotificationPayload from triggering a
            // user-visible NSAlert that looks like it came from
            // the system extension. The XPC path this replaces
            // enforced this via xpc_connection_set_peer_code_signing_
            // requirement on every connection; the file path enforces
            // it here.
            var entrySt = stat()
            if lstat(entry.path, &entrySt) != 0 {
                let err = String(cString: strerror(errno))
                logger.error("notification lstat \(uuid, privacy: .public): \(err, privacy: .public)")
                processed.insert(uuid)
                continue
            }
            if entrySt.st_uid != 0 {
                logger.error("notification rejecting non-root file uuid=\(uuid, privacy: .public) uid=\(entrySt.st_uid, privacy: .public)")
                processed.insert(uuid)
                continue
            }
            let data: Data
            do {
                data = try Data(contentsOf: entry)
            } catch {
                logger.error("notification read \(uuid, privacy: .public): \(error.localizedDescription, privacy: .public)")
                continue
            }
            let payload: BlockNotificationPayload
            do {
                payload = try decoder.decode(BlockNotificationPayload.self, from: data)
            } catch {
                logger.error("notification decode \(uuid, privacy: .public): \(error.localizedDescription, privacy: .public)")
                processed.insert(uuid)
                continue
            }
            processed.insert(uuid)
            // BlockAlertPresenter calls AppKit (NSAlert), which
            // requires the main thread. scan() runs on `queue`
            // (background serial), so dispatch the present
            // explicitly. Without this AppKit logs a "called on
            // non-main thread" warning and the alert can fail to
            // render under load.
            let captured = payload
            DispatchQueue.main.async { [weak self] in
                self?.presenter.present(captured)
            }
        }
        // Bound processed to UUIDs still present on disk. Without
        // this the set grows for the lifetime of the host-app
        // process; after the extension purges files older than
        // blockNotificationPurgeWindow, the matching UUIDs here are
        // stale book-keeping that can never trigger again.
        processed.formIntersection(stillOnDisk)
    }
}
