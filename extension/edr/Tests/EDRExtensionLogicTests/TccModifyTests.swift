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
        XCTAssertEqual((0...14).map { TccNames.reason(UInt32($0)) }, [
            "none", "error", "user_consent", "user_set", "system_set", "service_policy", "mdm_policy", "service_override_policy",
            "missing_usage_string", "prompt_timeout", "preflight_unknown", "entitled", "app_type_policy", "prompt_cancel", "unknown"
        ], "a reason a later SDK adds is a named gap, not a wrong name")
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

    // Encode then decode is the identity for any payload: arbitrary strings, any pid, and the responsible pid and signing each
    // present or absent on its own, as macOS reports them independently. Seeded, so a failure reproduces.
    func testThePayloadRoundTripsForAnyValues() throws {
        var rng = SeededGenerator(seed: 1185)
        let words = ["", "SystemPolicyAllFiles", "com.example.app", "/usr/local/bin/tool", "é\u{0}\"\\", "a/b c"]
        for _ in 0..<500 {
            let signing = { () -> CodeSigning? in
                guard Bool.random(using: &rng) else {
                    return nil
                }
                return CodeSigning(
                    teamID: words.randomElement(using: &rng) ?? "", signingID: words.randomElement(using: &rng) ?? "",
                    flags: UInt32.random(in: 0...UInt32.max, using: &rng), isPlatformBinary: Bool.random(using: &rng)
                )
            }
            let payload = TccModifyPayload(
                service: words.randomElement(using: &rng) ?? "", identity: words.randomElement(using: &rng) ?? "",
                identityType: TccNames.identityType(UInt32.random(in: 0...5, using: &rng)),
                updateType: TccNames.updateType(UInt32.random(in: 0...5, using: &rng)),
                right: TccNames.right(UInt32.random(in: 0...8, using: &rng)),
                reason: TccNames.reason(UInt32.random(in: 0...15, using: &rng)),
                instigatorPid: pid_t.random(in: pid_t.min...pid_t.max, using: &rng), instigatorCodeSigning: signing(),
                responsiblePid: Bool.random(using: &rng) ? nil : pid_t.random(in: 0...pid_t.max, using: &rng),
                responsibleCodeSigning: signing()
            )
            let decoded = try JSONDecoder().decode(TccModifyPayload.self, from: try JSONEncoder().encode(payload))
            XCTAssertEqual(decoded, payload)
        }
    }
}

/// SeededGenerator is SplitMix64, so the randomized test above is reproducible. The constants are the algorithm's published ones.
private struct SeededGenerator: RandomNumberGenerator {
    private static let increment: UInt64 = 0x9E37_79B9_7F4A_7C15
    private static let firstMultiplier: UInt64 = 0xBF58_476D_1CE4_E5B9
    private static let secondMultiplier: UInt64 = 0x94D0_49BB_1331_11EB
    private static let firstShift: UInt64 = 30
    private static let secondShift: UInt64 = 27
    private static let lastShift: UInt64 = 31

    private var state: UInt64
    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= Self.increment
        var mixed = state
        mixed = (mixed ^ (mixed >> Self.firstShift)) &* Self.firstMultiplier
        mixed = (mixed ^ (mixed >> Self.secondShift)) &* Self.secondMultiplier
        return mixed ^ (mixed >> Self.lastShift)
    }
}
