// The `tcc_modify` event (issue #1185): how the SDK's TCC enums are spelled on the wire, and the payload's wire keys.

@testable import EDRExtensionLogic
import XCTest

final class TccModifyTests: XCTestCase {
    // spec:endpoint-event-collection/tcc-permission-changes-are-reported/the-change-is-named-in-words
    func testTheSDKsValuesAreNamed() {
        XCTAssertEqual((0...4).map { TccNames.identityType(UInt32($0)) },
                       ["bundle_id", "executable_path", "policy_id", "file_provider_domain_id", "unknown"])
        XCTAssertEqual((0...4).map { TccNames.updateType(UInt32($0)) }, ["unknown", "create", "modify", "delete", "unknown"])
        XCTAssertEqual((0...7).map { TccNames.right(UInt32($0)) },
                       ["denied", "unknown", "allowed", "limited", "add_modify_added", "session_pid", "learn_more", "unknown"])
        XCTAssertEqual(TccNames.reason(2), "user_consent")
        XCTAssertEqual(TccNames.reason(3), "user_set")
        XCTAssertEqual(TccNames.reason(6), "mdm_policy")
        XCTAssertEqual(TccNames.reason(13), "prompt_cancel")
        XCTAssertEqual(TccNames.reason(14), "unknown", "a reason a later SDK adds is a named gap, not a wrong name")
    }

    // The shape captured on edr-dev from `tccutil reset DeveloperTool com.apple.Terminal`: a deletion by tccutil, made on behalf of an
    // SSH session. A process-less responsible is omitted rather than sent as null.
    func testThePayloadsWireKeys() throws {
        let payload = TccModifyPayload(
            service: "DeveloperTool", identity: "com.apple.Terminal", identityType: "bundle_id", updateType: "delete",
            right: "unknown", reason: "none", instigatorPid: 812,
            instigatorCodeSigning: CodeSigning(teamID: "", signingID: "com.apple.tccutil", flags: 0, isPlatformBinary: true),
            responsiblePid: nil, responsibleCodeSigning: nil
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        for key in [#""service":"DeveloperTool""#, #""identity_type":"bundle_id""#, #""update_type":"delete""#, #""right":"unknown""#,
                    #""reason":"none""#, #""instigator_pid":812"#, #""instigator_code_signing":"#] {
            XCTAssertTrue(json.contains(key), "missing \(key) in \(json)")
        }
        XCTAssertFalse(json.contains("responsible"), "absent responsible fields are omitted")
        let decoded = try JSONDecoder().decode(TccModifyPayload.self, from: try encoder.encode(payload))
        XCTAssertEqual(decoded.identity, "com.apple.Terminal")
        XCTAssertEqual(decoded.instigatorCodeSigning?.signingID, "com.apple.tccutil")
    }
}
