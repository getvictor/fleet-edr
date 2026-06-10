import EndpointSecurity
import Foundation
import os.log

// BTM launch-item handler split out of ESFSubscriber.swift to keep that file under SwiftLint's file_length /
// type_body_length caps (same rationale as ESFSubscriber+FileEvents.swift and CDHashHex.swift). It reaches
// ESFSubscriber's module-internal `serializer` and `onEvent`.
private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFBTM")

extension ESFSubscriber {
    /// handleBtmLaunchItemAdd surfaces a Background Task Management launch-item registration as a `btm_launch_item_add`
    /// event. macOS emits NOTIFY_BTM_LAUNCH_ITEM_ADD when launchd registers a LaunchAgent/LaunchDaemon or login item,
    /// regardless of how the plist landed on disk. This is the high-signal, low-volume persistence event the server's
    /// privilege_launchd_plist_write rule keys on (item_type=daemon, T1543.004). The rule's decision input is the
    /// REGISTERED EXECUTABLE's code-signing (the BTM instigator is Apple's smd for a launchctl-bootstrap registration
    /// and cannot discriminate). That signing is NOT computed here: a SIP-enabled host's extension sandbox denies the
    /// read of the registered executable, so the agent (an unsandboxed root daemon, off the ES callback thread) fills
    /// executable_code_signing from the on-disk binary before upload. See ADR-0008 and its 2026-05-29 amendment.
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
        default:
            // A future es_btm_item_type_t we don't map yet. "unknown" is in the wire schema enum; log it so the gap is
            // observable rather than silently dropped (the server filters to "daemon" today).
            itemType = "unknown"
            logger.error("btm_launch_item_add unmapped es_btm_item_type_t rawValue=\(item.item_type.rawValue)")
        }

        let itemPath = esTokenString(item.item_url)

        // The instigator process is forensic context only (it is Apple's smd for a launchctl-bootstrap registration, so
        // it cannot discriminate). Build its signing inline when present so the wire record is complete; the server rule
        // does not gate on it.
        var instigatorPID: pid_t = 0
        var instigatorCodeSigning: CodeSigning?
        if let instigator = event.instigator {
            let proc = instigator.pointee
            instigatorPID = audit_token_to_pid(proc.audit_token)
            instigatorCodeSigning = CodeSigning(
                teamID: esTokenString(proc.team_id),
                signingID: esTokenString(proc.signing_id),
                flags: proc.codesigning_flags,
                isPlatformBinary: proc.is_platform_binary
            )
        }

        // executable_path is the DECISION input's anchor: the agent reads this binary's on-disk code-signing and fills
        // executable_code_signing before upload. The extension cannot do it (a SIP-enabled host's sandbox denies the
        // read), so it ships nil here; the rule treats a still-nil signing as "cannot classify" and skips.
        let executablePath = esTokenString(event.executable_path)
        let payload = BtmLaunchItemAddPayload(
            itemType: itemType,
            itemPath: itemPath,
            executablePath: executablePath,
            legacy: item.legacy,
            managed: item.managed,
            uid: item.uid,
            executableCodeSigning: nil,
            instigatorPid: instigatorPID,
            instigatorCodeSigning: instigatorCodeSigning
        )

        if let data = serializer.serialize(eventType: "btm_launch_item_add", payload: payload) {
            logger.debug("btm_launch_item_add type=\(itemType) item=\(itemPath)")
            onEvent?(data)
        }
    }
}
