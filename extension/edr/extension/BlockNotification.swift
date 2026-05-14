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
/// MachServices declaration for the launchd registration.
let blockNotificationServiceName = "FDG8Q7N4CC.com.fleetdm.edr.notifications"

/// Stable wire-shape identifier for the block-notification message.
let blockNotificationMessageType = "application_control.block_notification"

/// Code-signing requirement both ends apply to the peer.
let blockNotificationPeerRequirement =
    "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""

/// BlockNotificationPayload mirrors the host app's Codable shape.
/// JSON tags are load-bearing — they have to stay in lockstep with
/// the host-app copy.
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
