import Foundation

/// Mirror of edr/edr/BlockNotification.swift for the extension side
/// of the same XPC channel. Both files have to ship identical
/// constants + payload shape; the alternative is a shared framework
/// target, which the current Xcode project deliberately doesn't have
/// (each binary is a thin slice with its own entitlements set).
///
/// Renaming any of these strings is a wire-shape contract break —
/// the host app's NotificationListener and this NotificationClient
/// would drift apart and the next AUTH_EXEC denial would silently
/// fail to surface a user-visible alert.

/// Mach service name vended by the host app. See edr/edr's
/// MachServices declaration for the launchd registration. The XPC
/// channel is the production-target transport; the demo cut uses
/// a file-based fallback (see blockNotificationDropDir) because
/// daemon → user-session XPC needs session-bridging plumbing.
let blockNotificationServiceName = "FDG8Q7N4CC.com.fleetdm.edr.notifications"

/// blockNotificationDropDir is the file-system rendezvous between
/// the extension (writer) and the host app (reader). Sticky-bit
/// mode (1777) on the directory lets the user-session host app
/// read the daemon-written files without us needing a privileged
/// helper. Per-file mode is 0644 so the user can read but only
/// root can replace. The host app processes each file once + leaves
/// it on disk; the extension purges its own writes on the next
/// notify if they're older than blockNotificationPurgeWindow.
let blockNotificationDropDir = "/private/tmp/fleet-edr-notify-drop"

/// blockNotificationPurgeWindow caps how long a notification file
/// lives on disk after the extension writes it. The host app's
/// FSEvents source picks up new files in under a second, so 5
/// minutes is much longer than the host-app processing time —
/// covers the "host app was offline when the notification fired"
/// case while preventing /private/tmp from filling up indefinitely
/// across a fleet of denied execs.
let blockNotificationPurgeWindow: TimeInterval = 300

/// Stable wire-shape identifier for the block-notification message.
let blockNotificationMessageType = "application_control.block_notification"

/// Code-signing requirement both ends apply to the peer.
let blockNotificationPeerRequirement =
    "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""

/// BlockNotificationPayload mirrors the host app's Codable shape.
/// JSON tags are load-bearing — they have to stay in lockstep with
/// the host-app copy.
/// See edr/edr/BlockNotification.swift for full field documentation.
/// In particular:
///   - ruleID and identifier travel for forensic correlation only.
///   - customMsg becomes the alert body verbatim when set; the
///     presenter falls back to a deterministic default otherwise.
///   - customURL is rendered as a "More info" button only when the
///     value parses as an http or https URL.
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
