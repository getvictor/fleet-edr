// BlockNotification tests: the extension and host-app sides of the
// application_control block-notification channel ship two copies of these constants
// + the Codable payload struct (see the header comment in BlockNotification.swift
// for why no shared framework target). These tests pin the canonical strings + the
// wire shape of BlockNotificationPayload so a stray edit on the extension side
// cannot silently drift away from the host-app side without a red gate. The host
// app's matching tests live alongside its own BlockNotification.swift copy.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class BlockNotificationTests: XCTestCase {
    // MARK: Wire-shape constants

    func testServiceNameIsCanonical() {
        XCTAssertEqual(blockNotificationServiceName, "FDG8Q7N4CC.com.fleetdm.edr.notifications")
    }

    func testDropDirIsCanonical() {
        XCTAssertEqual(blockNotificationDropDir, "/private/tmp/fleet-edr-notify-drop")
    }

    func testMessageTypeIsCanonical() {
        XCTAssertEqual(blockNotificationMessageType, "application_control.block_notification")
    }

    func testPeerRequirementIsCanonical() {
        // codesign(1) compiles this requirement string when both ends validate the
        // peer. A typo here = a silent peer-mismatch failure at runtime.
        XCTAssertEqual(
            blockNotificationPeerRequirement,
            "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""
        )
    }

    func testPurgeWindowIsFiveMinutes() {
        XCTAssertEqual(blockNotificationPurgeWindow, 300)
    }

    // MARK: BlockNotificationPayload Codable round-trip

    func testPayloadRoundTrip() throws {
        let original = BlockNotificationPayload(
            ruleID: "app_control:42",
            ruleType: "BINARY",
            identifier: String(repeating: "f", count: 64),
            customMsg: "Blocked by policy",
            customURL: "https://example.test/info",
            binaryPath: "/bin/blocked",
            policyID: 7,
            policyVersion: 12
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let encoded = try encoder.encode(original)
        let decoded = try JSONDecoder().decode(BlockNotificationPayload.self, from: encoded)
        XCTAssertEqual(decoded.ruleID, original.ruleID)
        XCTAssertEqual(decoded.ruleType, original.ruleType)
        XCTAssertEqual(decoded.identifier, original.identifier)
        XCTAssertEqual(decoded.customMsg, original.customMsg)
        XCTAssertEqual(decoded.customURL, original.customURL)
        XCTAssertEqual(decoded.binaryPath, original.binaryPath)
        XCTAssertEqual(decoded.policyID, original.policyID)
        XCTAssertEqual(decoded.policyVersion, original.policyVersion)

        // Pin the literal wire bytes so the host-app reader can decode this
        // exact byte stream without surprise. Each entry below is a key the host-app
        // BlockNotificationPayload's CodingKeys also names: rename either side and
        // both these tests + the host-app copy must change.
        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"rule_id\":\"app_control:42\""))
        XCTAssertTrue(json.contains("\"rule_type\":\"BINARY\""))
        XCTAssertTrue(json.contains("\"custom_msg\":\"Blocked by policy\""))
        XCTAssertTrue(json.contains("\"custom_url\":\"https:\\/\\/example.test\\/info\""))
        XCTAssertTrue(json.contains("\"binary_path\":\"\\/bin\\/blocked\""))
        XCTAssertTrue(json.contains("\"policy_id\":7"))
        XCTAssertTrue(json.contains("\"policy_version\":12"))
    }

    func testPayloadOmitsNilOptionalsOnEncode() throws {
        // customMsg + customURL are optional. The host app falls back to its default
        // alert body when the field is ABSENT (issue #87 spec, not when explicitly
        // null), so the wire must omit the keys entirely.
        let payload = BlockNotificationPayload(
            ruleID: "r", ruleType: "BINARY", identifier: "x",
            customMsg: nil, customURL: nil,
            binaryPath: "/x", policyID: 1, policyVersion: 1
        )
        let json = String(data: try JSONEncoder().encode(payload), encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains("custom_msg"))
        XCTAssertFalse(json.contains("custom_url"))
    }

    func testPayloadDecodesMissingOptionalsAsNil() throws {
        // Companion to the omit-on-encode test above: the host app emits payloads
        // without optional fields, the extension's decoder accepts them as nil.
        let wire = """
        {"binary_path":"/x","identifier":"x","policy_id":1,"policy_version":1,"rule_id":"r","rule_type":"BINARY"}
        """
        let decoded = try JSONDecoder().decode(BlockNotificationPayload.self, from: Data(wire.utf8))
        XCTAssertNil(decoded.customMsg)
        XCTAssertNil(decoded.customURL)
        XCTAssertEqual(decoded.ruleID, "r")
        XCTAssertEqual(decoded.binaryPath, "/x")
    }
}
