import EndpointSecurity
import Foundation
import os.log

// TCC modification handler split out of ESFSubscriber.swift to keep that file under SwiftLint's length caps, as the BTM handler is.
// It reaches ESFSubscriber's module-internal `serializer` and `onEvent`.
private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFTCC")

extension ESFSubscriber {
    /// handleTccModify surfaces a TCC permission record being created, modified or deleted as a `tcc_modify` event (issue #1185).
    /// macOS emits NOTIFY_TCC_MODIFY for every change tccd records, whether a user answered a prompt, changed a switch in System
    /// Settings, an MDM profile set it, or a tool such as `tccutil` reset it, which is what lets a rule see an app being handed Full
    /// Disk Access, Accessibility or Screen Recording.
    func handleTccModify(_ msg: es_message_t) {
        let event = msg.event.tcc_modify.pointee
        let instigator = event.instigator?.pointee
        let responsible = event.responsible?.pointee
        let payload = TccModifyPayload(
            service: esTokenString(event.service),
            identity: esTokenString(event.identity),
            identityType: TccNames.identityType(event.identity_type.rawValue),
            updateType: TccNames.updateType(event.update_type.rawValue),
            right: TccNames.right(event.right.rawValue),
            reason: TccNames.reason(event.reason.rawValue),
            instigatorPid: audit_token_to_pid(event.instigator_token),
            instigatorCodeSigning: instigator.map { Self.codeSigning(of: $0) },
            responsiblePid: event.responsible_token.map { audit_token_to_pid($0.pointee) },
            responsibleCodeSigning: responsible.map { Self.codeSigning(of: $0) }
        )
        if let data = serializer.serialize(eventType: "tcc_modify", payload: payload, kernelTimeNs: kernelEventTimeNs(msg.time)) {
            logger.debug("tcc_modify service=\(payload.service, privacy: .public) update=\(payload.updateType, privacy: .public)")
            onEvent?(data)
        }
    }
}
