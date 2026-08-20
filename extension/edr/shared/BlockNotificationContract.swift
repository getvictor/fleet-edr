import Foundation

/// The wire contract for the AUTH_EXEC block notification, shared by every target that speaks it.
///
/// The extension writes these notifications and the host app reads them, so the constants and the payload shape have to agree exactly.
/// They used to be maintained as two hand-synchronised copies, one in `extension/` and one in `edr/`, each carrying a comment warning
/// that renaming any string here is a silent wire-shape break: the host app's NotificationListener and the extension's
/// NotificationClient would drift apart and the next denial would simply fail to surface an alert, with nothing failing loudly.
///
/// A warning comment is not a mechanism. The file now lives in `shared/`, which is folder-synchronised into every target that needs
/// it, so the two sides cannot drift because there is only one definition. That is the same arrangement `XPCEventServer.swift`
/// already uses, and it is why no shared framework target is required: Xcode's synchronised groups compile the same source into each
/// binary, and each binary keeps its own entitlements.
///
/// Renaming anything here is still a contract break. It is now a contract break that changes both sides at once.

/// Mach service name the host app vends so the system extension can push a desktop notification on every AUTH_EXEC denial. The
/// team-id prefix matches the convention the agent-to-extension XPC channel already uses
/// (`FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc`). See the host app's MachServices declaration for the launchd registration.
///
/// This is the production-target transport. The demo cut uses a file-based fallback (see `blockNotificationDropDir`) because a daemon
/// in the system bootstrap reaching a user-session GUI Mach service needs a session-bridging helper that is out of scope for the demo.
/// A production deployment with the LaunchAgent installed at /Library/LaunchAgents switches back to the XPC path.
let blockNotificationServiceName = "FDG8Q7N4CC.com.fleetdm.edr.notifications"

/// Drop directory for the file-based fallback, shared by the extension (writer, running as root) and the host app (reader, running as
/// the user). The extension creates it with the sticky bit (mode 1777) so the user-session host app can read daemon-written files
/// without a privileged helper, and writes each file 0644 so the user can read it but only root can replace it. The host app processes
/// each file once and leaves it on disk; the extension purges its own writes older than `blockNotificationPurgeWindow` on the next
/// notify.
let blockNotificationDropDir = "/private/tmp/fleet-edr-notify-drop"

/// How long a dropped notification file survives before the extension purges it on a later notify. Only the writer acts on this, but
/// it belongs with the rest of the contract: it is what bounds how long a reader can still find a given drop.
let blockNotificationPurgeWindow: TimeInterval = 300

/// Message type discriminator carried in the payload envelope.
let blockNotificationMessageType = "application_control.block_notification"

/// Code-signing requirement each side pins on its XPC peer.
let blockNotificationPeerRequirement =
    "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""

/// The notification body. The CodingKeys are snake_case because this crosses the XPC boundary as JSON; changing a key here changes the
/// wire format for both sides at once, which is the point of this file living in one place.
struct BlockNotificationPayload: Codable, Sendable {
    let ruleID: String
    let ruleType: String
    let identifier: String
    let customMsg: String?
    let customURL: String?
    let binaryPath: String
    let policyID: Int64
    let policyVersion: Int64

    enum CodingKeys: String, CodingKey {
        case ruleID = "rule_id"
        case ruleType = "rule_type"
        case identifier
        case customMsg = "custom_msg"
        case customURL = "custom_url"
        case binaryPath = "binary_path"
        case policyID = "policy_id"
        case policyVersion = "policy_version"
    }
}
