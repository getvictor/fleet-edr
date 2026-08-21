// BlockNotification tests: the extension and host-app sides of the
// application_control block-notification channel share ONE definition of these
// constants + the Codable payload struct, in shared/BlockNotificationContract.swift
// (see that file's header for why a folder-synchronised group rather than a shared
// framework target). Drift between the two sides is now structurally impossible, so
// what these tests still buy is the OTHER half: they pin the canonical strings and
// the literal wire bytes, so renaming a key stays a deliberate, visible contract
// change instead of a silent one that compiles cleanly on both sides at once.

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

        // Pin the COMPLETE wire bytes, not a set of substrings. Both sides now compile the same CodingKeys, so a rename can no longer
        // desynchronise them, but it still silently changes what goes over the wire. Equality against the whole encoding is what makes
        // that visible, and unlike substring checks it also fails when a field is ADDED, which is the case a reader has to cope with.
        // `.sortedKeys` above makes the encoding deterministic, so this is a stable literal rather than a dictionary-order coin flip.
        let json = String(data: encoded, encoding: .utf8)
        let expectedJSON = "{\"binary_path\":\"\\/bin\\/blocked\","
            + "\"custom_msg\":\"Blocked by policy\","
            + "\"custom_url\":\"https:\\/\\/example.test\\/info\","
            + "\"identifier\":\"\(String(repeating: "f", count: 64))\","
            + "\"policy_id\":7,"
            + "\"policy_version\":12,"
            + "\"rule_id\":\"app_control:42\","
            + "\"rule_type\":\"BINARY\"}"
        XCTAssertEqual(json, expectedJSON)
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
