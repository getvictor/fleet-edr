import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "NotificationClient")

/// NotificationClient is the extension's outbound XPC channel to the
/// host app's block-notification listener. The decision engine fires
/// `notify(_:)` after returning DENY to the kernel, so the modal pops
/// on the user's desktop without ever blocking the AUTH_EXEC callback.
///
/// Concurrency: every method routes through a dedicated serial queue.
/// xpc_connection_t is otherwise free-threaded but using a single
/// queue gives us a predictable ordering (the second blocked exec's
/// notification can't beat the first one's), and keeps the host-app
/// listener from receiving overlapping messages on the same
/// connection.
///
/// Lifecycle: the connection is lazy. We open it on the first
/// `notify` and keep it for subsequent calls so the steady-state path
/// is a single xpc_connection_send_message. Reconnection on peer
/// disconnect is delegated to the next `notify` — XPC's
/// activate-after-cancel pattern doesn't apply once a connection
/// hits the invalid state.
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
    private var connection: xpc_connection_t?

    private init() {}

    /// notify enqueues the block-notification message on the
    /// outbound XPC connection. Fire-and-forget by design: the
    /// extension already returned DENY to the kernel and the alert
    /// is post-hoc UX, so a missing host app shouldn't error out
    /// the call site. Failures are logged and swallowed.
    func notify(_ payload: BlockNotificationPayload) {
        queue.async { [weak self] in
            guard let self else { return }
            guard let data = self.encodePayload(payload) else { return }
            guard let conn = self.acquireConnection() else {
                // Code-signing install failed; the connection was
                // cancelled in acquireConnection. Drop the message —
                // the call site already returned DENY to the kernel,
                // so swallowing the alert is the safe direction.
                return
            }
            let msg = xpc_dictionary_create_empty()
            xpc_dictionary_set_string(msg, "type", blockNotificationMessageType)
            data.withUnsafeBytes { buf in
                guard let baseAddress = buf.baseAddress else { return }
                xpc_dictionary_set_data(msg, "data", baseAddress, buf.count)
            }
            xpc_connection_send_message(conn, msg)
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

    /// acquireConnection returns the cached connection or opens a
    /// fresh one. Called only from `queue`, so the assignment
    /// doesn't need locking. The event handler resets `connection`
    /// to nil on invalidation so the next call reopens.
    ///
    /// Returns nil when the peer code-signing requirement fails to
    /// install. We fail closed in that case rather than send to an
    /// unvalidated peer — a spoofed notification surface could
    /// otherwise present arbitrary modal text to the user.
    ///
    /// Bootstrap-domain note (Copilot, PR #157): the extension is a
    /// LaunchDaemon and its Mach lookups land in the system
    /// bootstrap namespace, while a per-user LaunchAgent registers
    /// the notification service in the GUI bootstrap. The demo
    /// dry-run runs the host app inside the same Terminal session
    /// the operator opens, so the two namespaces overlap and the
    /// connect succeeds. Production deployment with the LaunchAgent
    /// installed at /Library/LaunchAgents needs a session-bridging
    /// helper or sysext-side `xpc_connection_set_target_uid`
    /// pinning; tracked as Phase B follow-up alongside the
    /// notification-center integration work.
    private func acquireConnection() -> xpc_connection_t? {
        if let existing = connection {
            return existing
        }
        let conn = xpc_connection_create_mach_service(
            blockNotificationServiceName, queue, 0
        )
        // Validate the host app's code signature so a non-Fleet
        // process can't impersonate the notification surface. Same
        // posture as the agent ↔ extension channel.
        let req = xpc_connection_set_peer_code_signing_requirement(conn, blockNotificationPeerRequirement)
        if req != 0 {
            logger.error("notification client peer code-signing install failed; failing closed: \(req, privacy: .public)")
            xpc_connection_cancel(conn)
            return nil
        }
        xpc_connection_set_event_handler(conn) { [weak self] event in
            self?.handleConnectionEvent(event)
        }
        xpc_connection_activate(conn)
        connection = conn
        return conn
    }

    /// handleConnectionEvent observes XPC error events so we can
    /// drop the cached connection and let `acquireConnection`
    /// reopen on the next notify. The expected error path is the
    /// host app exiting (user logged out, the LaunchAgent stopped);
    /// reopening on the next notify covers re-login automatically.
    ///
    /// The event handler is dispatched on `queue` by XPC, so
    /// `connection = nil` is a direct in-handler write rather than a
    /// queue.async hop — no concurrent reader can observe a torn
    /// state and the next queued notify sees the nil and reopens.
    private func handleConnectionEvent(_ event: xpc_object_t) {
        let type = xpc_get_type(event)
        if type == XPC_TYPE_ERROR {
            connection = nil
            logger.info("notification client connection invalidated; will reopen on next notify")
        }
    }
}
