import EndpointSecurity
import Foundation
import os.log

// BTM launch-item handler split out of ESFSubscriber.swift to keep that file under SwiftLint's file_length /
// type_body_length caps (same rationale as ESFSubscriber+FileEvents.swift and CDHashHex.swift). It reaches
// ESFSubscriber's module-internal `serializer`, `onEvent`, and `extractCodeSigning`.
private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFBTM")

extension ESFSubscriber {
    /// handleBtmLaunchItemAdd surfaces a Background Task Management launch-item registration as a `btm_launch_item_add`
    /// event. macOS emits NOTIFY_BTM_LAUNCH_ITEM_ADD when launchd registers a LaunchAgent/LaunchDaemon or login item,
    /// regardless of how the plist landed on disk - the high-signal, low-volume persistence event the server's
    /// privilege_launchd_plist_write rule keys on (item_type=daemon, T1543.004). The instigator's code-signing rides
    /// inline so the rule needs no pid->process correlation. See ADR-0008.
    func handleBtmLaunchItemAdd(_ msg: es_message_t) {
        let event = msg.event.btm_launch_item_add.pointee
        let item = event.item.pointee

        let itemType: String
        switch item.item_type {
        case ES_BTM_ITEM_TYPE_USER_ITEM: itemType = "user_item"
        case ES_BTM_ITEM_TYPE_APP: itemType = "app"
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM: itemType = "login_item"
        case ES_BTM_ITEM_TYPE_AGENT: itemType = "agent"
        case ES_BTM_ITEM_TYPE_DAEMON: itemType = "daemon"
        default: itemType = "unknown"
        }

        let itemPath = esTokenString(item.item_url)

        // The BTM event carries the instigator process (the one that registered the item) inline; the server rule reads
        // its code-signing directly. Optional: absent for boot-time / launchd-internal registrations.
        var instigatorPID: pid_t = 0
        var instigatorCodeSigning: CodeSigning?
        if let instigator = event.instigator {
            instigatorPID = audit_token_to_pid(instigator.pointee.audit_token)
            instigatorCodeSigning = extractCodeSigning(from: instigator.pointee)
        }

        let payload = BtmLaunchItemAddPayload(
            itemType: itemType,
            itemPath: itemPath,
            executablePath: esTokenString(event.executable_path),
            legacy: item.legacy,
            managed: item.managed,
            uid: item.uid,
            instigatorPid: instigatorPID,
            instigatorCodeSigning: instigatorCodeSigning
        )

        if let data = serializer.serialize(eventType: "btm_launch_item_add", payload: payload) {
            logger.debug("btm_launch_item_add type=\(itemType) item=\(itemPath)")
            onEvent?(data)
        }
    }
}
