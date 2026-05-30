import EndpointSecurity
import Foundation
import Security
import os.log

// BTM launch-item handler split out of ESFSubscriber.swift to keep that file under SwiftLint's file_length /
// type_body_length caps (same rationale as ESFSubscriber+FileEvents.swift and CDHashHex.swift). It reaches
// ESFSubscriber's module-internal `serializer` and `onEvent`.
private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFBTM")

extension ESFSubscriber {
    /// handleBtmLaunchItemAdd surfaces a Background Task Management launch-item registration as a `btm_launch_item_add`
    /// event. macOS emits NOTIFY_BTM_LAUNCH_ITEM_ADD when launchd registers a LaunchAgent/LaunchDaemon or login item,
    /// regardless of how the plist landed on disk - the high-signal, low-volume persistence event the server's
    /// privilege_launchd_plist_write rule keys on (item_type=daemon, T1543.004). The rule's decision input is the
    /// REGISTERED EXECUTABLE's code-signing, computed here out-of-band (the BTM instigator is Apple's smd for a
    /// launchctl-bootstrap registration and cannot discriminate). See ADR-0008 and its 2026-05-29 amendment.
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

        // The DECISION input: the registered executable's code-signing, evaluated out-of-band (BTM carries no signing for
        // the to-be-launched executable). nil when absent/unreadable -> the rule skips (cannot classify).
        let executablePath = esTokenString(event.executable_path)
        let payload = BtmLaunchItemAddPayload(
            itemType: itemType,
            itemPath: itemPath,
            executablePath: executablePath,
            legacy: item.legacy,
            managed: item.managed,
            uid: item.uid,
            executableCodeSigning: evaluateExecutableSigning(path: executablePath),
            instigatorPid: instigatorPID,
            instigatorCodeSigning: instigatorCodeSigning
        )

        if let data = serializer.serialize(eventType: "btm_launch_item_add", payload: payload) {
            logger.debug("btm_launch_item_add type=\(itemType) item=\(itemPath)")
            onEvent?(data)
        }
    }
}

// evaluateExecutableSigning reads the registered executable's code-signing out-of-band via SecStaticCode. BTM carries
// signing only for the instigator/app PROCESSES, never for the to-be-launched executable, so the server rule's decision
// input (ADR-0008 amendment) is computed here. Returns nil when the path is empty or SecStaticCode cannot open the file
// (absent/unreadable) - the rule treats a nil executable_code_signing as "cannot classify" and skips. A present but
// unsigned binary (an ad-hoc/unsigned dropper, the prime attacker case) returns empty team/signing ids, which the rule
// fires on. Mirrors the proven SecCode form in SigningInfoFallback.swift. Notarization (is_notarized) is a planned
// enhancement (SecAssessment); v1 omits it so the rule falls back to the platform-binary check + team-ID allowlist.
private func evaluateExecutableSigning(path: String) -> CodeSigning? {
    guard !path.isEmpty else { return nil }
    let url = URL(fileURLWithPath: path) as CFURL
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess, let code = staticCode else {
        return nil
    }
    var teamID = ""
    var signingID = ""
    var infoDict: CFDictionary?
    if SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoDict) == errSecSuccess,
       let info = infoDict as? [String: Any] {
        teamID = info[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        signingID = info[kSecCodeInfoIdentifier as String] as? String ?? ""
    }
    return CodeSigning(teamID: teamID, signingID: signingID, flags: 0, isPlatformBinary: satisfiesAppleAnchor(code))
}

// satisfiesAppleAnchor returns true iff the static code validates against the "anchor apple" designated requirement (an
// Apple-shipped OS binary). Used as the executable's is_platform_binary signal, since the BTM event has no platform flag
// for the to-be-launched executable. A creation/validity failure is a conservative false (treated as not Apple).
private func satisfiesAppleAnchor(_ code: SecStaticCode) -> Bool {
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
          let req = requirement else {
        return false
    }
    // .noNetworkAccess restricts validation to LOCAL checks. An Endpoint Security callback thread must never block on an
    // OCSP/CRL revocation fetch: that network traffic can itself trigger ESF events and deadlock the extension (Gemini
    // CRITICAL). "anchor apple" is satisfiable entirely from the on-disk chain, so local-only is sufficient.
    return SecStaticCodeCheckValidity(code, .noNetworkAccess, req) == errSecSuccess
}
