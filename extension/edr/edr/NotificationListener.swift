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
/// Cleanup: the extension owns the dropped files (root-owned, mode
/// 0644). The host app can read but not unlink under sticky-bit
/// rules. The extension purges its own files older than
/// blockNotificationPurgeWindow on every notify, so the directory
/// stays bounded.
final class NotificationListener {
    private let dropDir: String
    private let presenter: BlockAlertPresenter
    private let queue = DispatchQueue(label: "com.fleetdm.edr.notification-listener")
    private var source: DispatchSourceFileSystemObject?
    private var fd: Int32 = -1
    // processed records the UUIDs we've already presented to avoid
    // double-firing if FSEvents fires repeatedly for the same write
    // (which the docs say can happen on rename / chmod sequences).
    private var processed: Set<String> = []

    init(dropDir: String = blockNotificationDropDir, presenter: BlockAlertPresenter) {
        self.dropDir = dropDir
        self.presenter = presenter
    }

    func start() {
        ensureDropDirectory()
        let descriptor = open(dropDir, O_EVTONLY)
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

    /// ensureDropDirectory creates the drop directory if absent so
    /// the FSEvents source has something to open. The extension
    /// (root) is the canonical creator + sets the sticky 1777 mode;
    /// this is the user-side fallback when the host app starts
    /// before any AUTH_EXEC denial has triggered the extension's
    /// own ensureDropDirectory. createDirectory is idempotent.
    private func ensureDropDirectory() {
        try? FileManager.default.createDirectory(
            atPath: dropDir,
            withIntermediateDirectories: true,
            attributes: nil,
        )
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
        for entry in entries where entry.pathExtension == "json" {
            let uuid = entry.deletingPathExtension().lastPathComponent
            if processed.contains(uuid) { continue }
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
            presenter.present(payload)
        }
    }
}
