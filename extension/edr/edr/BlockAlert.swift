import AppKit
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr", category: "BlockAlert")

/// BlockAlertPresenter is the protocol the XPC listener calls into.
/// Real life uses BlockAlertPresenterAppKit; tests use a fake.
protocol BlockAlertPresenter {
    func present(_ notification: BlockNotificationPayload)
}

/// BlockAlertPresenterAppKit renders one NSAlert per accepted
/// block-notification. The visual is intentionally Santa-shaped:
/// an icon-bearing modal with the rule's `custom_msg` in the body
/// and a "More info" / "Dismiss" button pair. The host app runs as
/// an NSApplication with accessory activation policy so the alert
/// appears as a floating modal without putting an icon in the Dock.
///
/// Serialisation: NSAlert.runModal blocks the calling thread, so we
/// process notifications on a dedicated serial queue and hop to the
/// main queue with `DispatchQueue.main.sync` to show each alert.
/// The queue's serial nature means two blocked execs back-to-back
/// produce two modals shown one after the other — never overlapping
/// — and the receive ordering matches the AUTH_EXEC denial ordering.
///
/// Dedup: a (rule_id, binary_path) tuple seen within the last
/// `dedupWindow` is suppressed. The extension's AUTH_EXEC handler
/// fires on every exec attempt, and a misbehaving caller might
/// retry many times in a tight loop; we don't want to bury the
/// user's screen in modals.
final class BlockAlertPresenterAppKit: NSObject, BlockAlertPresenter {
    private let queue = DispatchQueue(label: "com.fleetdm.edr.block-alert")
    private let dedupWindow: TimeInterval
    private var recent: [String: Date] = [:]

    /// dedupWindow defaults to 30 seconds. Long enough that the
    /// human at the keyboard pressing Cmd-Click → Open repeatedly on
    /// the same app doesn't paper their screen, short enough that a
    /// later genuine re-exec attempt still surfaces visibly.
    init(dedupWindow: TimeInterval = 30) {
        self.dedupWindow = dedupWindow
    }

    func present(_ notification: BlockNotificationPayload) {
        queue.async { [weak self] in
            guard let self else { return }
            // Dedup is re-checked synchronously on the main queue
            // right before the modal is shown — see showAlert.
            // Checking here too would only suppress arrivals while
            // the queue is idle; a long-open modal can wait minutes,
            // during which more duplicates accumulate and would
            // pass an early-stage dedup with a stale timestamp.
            DispatchQueue.main.sync {
                self.showAlert(notification)
            }
        }
    }

    /// shouldDedup returns true when we've shown an alert with the
    /// same `(rule_id, binary_path)` tuple within `dedupWindow`.
    /// Called from showAlert on the main queue — the synchronous
    /// hop in present() guarantees we re-check at presentation time
    /// rather than enqueue time, so a 60s-open modal followed by 10
    /// queued duplicates produces one new alert (the first that
    /// arrives past the window), not all 10 in succession.
    private func shouldDedup(_ notification: BlockNotificationPayload) -> Bool {
        let key = notification.ruleID + "|" + notification.binaryPath
        let now = Date()
        // Purge entries older than the window to keep the map bounded.
        recent = recent.filter { $0.value.addingTimeInterval(dedupWindow) > now }
        if let last = recent[key], last.addingTimeInterval(dedupWindow) > now {
            return true
        }
        recent[key] = now
        return false
    }

    private func showAlert(_ notification: BlockNotificationPayload) {
        if shouldDedup(notification) {
            logger.info("suppressed duplicate block alert within dedup window")
            return
        }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Application blocked: \(binaryDisplayName(notification.binaryPath))"
        alert.informativeText = body(notification)

        let dismissButton = alert.addButton(withTitle: "Dismiss")
        dismissButton.tag = NSApplication.ModalResponse.alertFirstButtonReturn.rawValue

        // moreURL is non-nil iff the operator authored a "More info"
        // link AND it parsed to an http/https URL. Other schemes
        // (file://, custom URI handlers) are rejected so a hostile
        // rule author can't trigger arbitrary URL handlers from a
        // single click on the alert.
        var moreURL: URL?
        if let urlString = notification.customURL,
           let url = URL(string: urlString),
           url.scheme == "https" || url.scheme == "http" {
            let moreButton = alert.addButton(withTitle: "More info")
            moreButton.tag = NSApplication.ModalResponse.alertSecondButtonReturn.rawValue
            moreURL = url
        }

        // Bring the host app forward so the modal lands on top of
        // whatever window the user was looking at.
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        if response == .alertSecondButtonReturn, let url = moreURL {
            NSWorkspace.shared.open(url)
        }
    }

    /// body picks the alert's informativeText: prefers the
    /// operator-authored custom message when set, otherwise renders
    /// a deterministic default (Santa-shaped: "<binary> was blocked
    /// by your organization's security policy").
    private func body(_ notification: BlockNotificationPayload) -> String {
        if let custom = notification.customMsg, !custom.isEmpty {
            return custom
        }
        let name = binaryDisplayName(notification.binaryPath)
        return "\(name) was blocked by your organization's security policy."
    }

    /// binaryDisplayName picks the last path component when it's
    /// useful, otherwise falls back to the full path. The hash
    /// path-component cases (".", "/", "") shouldn't happen with
    /// real ESF input but the guard keeps the alert text sane in
    /// the synthetic-fixture regression-test path.
    private func binaryDisplayName(_ path: String) -> String {
        let name = (path as NSString).lastPathComponent
        if name.isEmpty || name == "." || name == "/" {
            return path
        }
        return name
    }
}
