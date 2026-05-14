import Foundation

/// Mach service name the host app vends so the system extension can
/// push a desktop notification on every AUTH_EXEC denial. The
/// team-id prefix matches the convention the agent ↔ extension XPC
/// channel already uses (`FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc`).
///
/// Visibility: declared in `edr/edr/Info.plist`'s `MachServices` so
/// launchd registers the name when the host app is launched via the
/// LaunchAgent plist shipped alongside this file. For the demo dry-
/// run on the SIP-disabled VM the host app can also be started
/// manually with `edr notify`; the listener self-registers the name
/// in that case too.
let blockNotificationServiceName = "FDG8Q7N4CC.com.fleetdm.edr.notifications"

/// Stable wire-shape identifier for the block-notification message.
/// Mirrors the `type` key convention the extension's existing XPC
/// peer protocol uses (`application_control.update`, `hello`).
let blockNotificationMessageType = "application_control.block_notification"

/// Code-signing requirement both ends apply to the peer. Same team
/// ID as the agent ↔ extension channel: any binary signed by Fleet
/// Device Management can speak the protocol. Phase B extends this
/// with notarization checks for production deployments.
let blockNotificationPeerRequirement =
    "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""

/// BlockNotificationPayload is the JSON shape the extension serialises
/// into the XPC message's `data` field. Field tags match the
/// snake_case wire convention used elsewhere in the project (see
/// schema/events.json). The host app decodes via Codable.
///
/// Both ruleID and policyID/policyVersion travel in the payload so the
/// host app can include them in any "More info" deep-link path or
/// future analytics ping without re-querying the server.
struct BlockNotificationPayload: Codable, Sendable {
    /// Stable rule identifier (e.g. "app_control:42") that the
    /// server alert mapping uses. The host app surfaces it in the
    /// alert text only when no custom_msg is set.
    let ruleID: String
    /// Rule type token (BINARY today; the others come post-demo).
    let ruleType: String
    /// Matched identifier value — the file SHA-256 for a BINARY
    /// rule. The host app shows the first 12 hex chars so the
    /// alert text doesn't sprawl across the screen.
    let identifier: String
    /// Operator-authored custom message. When set, this is the
    /// alert's main body verbatim.
    let customMsg: String?
    /// Operator-authored "More info" URL. When set + parsable,
    /// the alert renders a "More info" button that opens the URL
    /// in the user's default browser.
    let customURL: String?
    /// Absolute path of the binary the extension denied. The host
    /// app shows the binary's basename in the alert headline so a
    /// row reads "Application blocked: Calculator" rather than
    /// drowning the column in a full path.
    let binaryPath: String
    /// Policy id from the snapshot the extension was holding at
    /// decision time. Travels for forensic correlation only —
    /// today's host-app UI doesn't render it.
    let policyID: Int64
    /// Policy version from the same snapshot. Same forensic-only
    /// rationale.
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
