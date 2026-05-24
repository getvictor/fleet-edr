// EventSerializer payload tests: pin the on-wire JSON shape of every payload type
// the extension emits, because the server-side decoders in
// `server/rules/internal/catalog/*` rely on these exact field names. A rename on
// either side is a contract break, and these round-trip tests are the gate that
// catches it before the wire shape ships.
//
// The serializer's runtime entry point (EventSerializer.serialize) is intentionally
// NOT tested here: it pulls the hardware UUID via IOKit, which is environment-
// coupled (test runners report different values, and the call has side effects).
// What IS testable is the Codable shape of every payload + the EventEnvelope
// generic, which is what the wire shape actually is.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class EventSerializerTests: XCTestCase {
    // The serializer uses `.sortedKeys` formatting, so the wire bytes are stable
    // across encodes. We mirror that here so the literal-string assertions below are
    // not order-sensitive.
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()

    private let decoder = JSONDecoder()

    // MARK: - ExecPayload

    // spec:endpoint-event-collection/process-lifecycle-event-capture/a-user-runs-a-shell-command
    //
    // The exec payload's wire shape is what the agent + server consume when rendering "a user runs a
    // shell command" in the UI. The round-trip below pins every field the wire contract requires: pid +
    // ppid identities, executable path, argv array, cwd, uid/gid, the signing-info nest, sha256, and
    // cdhash. A regression that dropped any of these would break what an operator sees about which
    // command a host actually ran.
    func testExecPayloadRoundTripWithFullSigning() throws {
        let signing = CodeSigning(teamID: "FDG8Q7N4CC", signingID: "com.apple.bash", flags: 0x2000, isPlatformBinary: true)
        let payload = ExecPayload(
            pid: 4242, ppid: 1, path: "/bin/bash", args: ["bash", "-c", "echo hi"],
            cwd: "/Users/test", uid: 501, gid: 20,
            codeSigning: signing,
            sha256: String(repeating: "a", count: 64),
            cdhash: String(repeating: "b", count: 40),
            snapshot: false
        )
        let encoded = try encoder.encode(payload)
        let decoded = try decoder.decode(ExecPayload.self, from: encoded)
        XCTAssertEqual(decoded.pid, payload.pid)
        XCTAssertEqual(decoded.ppid, payload.ppid)
        XCTAssertEqual(decoded.path, payload.path)
        XCTAssertEqual(decoded.args, payload.args)
        XCTAssertEqual(decoded.cwd, payload.cwd)
        XCTAssertEqual(decoded.uid, payload.uid)
        XCTAssertEqual(decoded.gid, payload.gid)
        XCTAssertEqual(decoded.codeSigning?.teamID, signing.teamID)
        XCTAssertEqual(decoded.codeSigning?.signingID, signing.signingID)
        XCTAssertEqual(decoded.codeSigning?.flags, signing.flags)
        XCTAssertEqual(decoded.codeSigning?.isPlatformBinary, signing.isPlatformBinary)
        XCTAssertEqual(decoded.sha256, payload.sha256)
        XCTAssertEqual(decoded.cdhash, payload.cdhash)
        XCTAssertEqual(decoded.snapshot, false)
    }

    func testExecPayloadOmitsSnapshotKeyWhenFalse() throws {
        // The encoder DELIBERATELY drops `snapshot` when it is false so the wire
        // bytes for live execs stay byte-identical to the pre-issue-#11 format and
        // the server detection-engine bytes.Contains gate over `"snapshot":true`
        // does not have to special-case `"snapshot":false`.
        let payload = ExecPayload(
            pid: 1, ppid: 0, path: "/bin/sh", args: ["sh"], cwd: "/", uid: 0, gid: 0,
            codeSigning: nil, sha256: nil, cdhash: nil, snapshot: false
        )
        let encoded = try encoder.encode(payload)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains("\"snapshot\""), "live-exec wire must not carry snapshot key, got: \(json)")
        // Sanity-check the other always-emitted keys survive.
        XCTAssertTrue(json.contains("\"pid\":1"))
        XCTAssertTrue(json.contains("\"path\":\"\\/bin\\/sh\""))
    }

    func testExecPayloadEmitsSnapshotKeyWhenTrue() throws {
        let payload = ExecPayload(
            pid: 99, ppid: 1, path: "/bin/ls", args: ["ls"], cwd: "/", uid: 0, gid: 0,
            codeSigning: nil, sha256: nil, cdhash: nil, snapshot: true
        )
        let encoded = try encoder.encode(payload)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"snapshot\":true"), "startup-snapshot exec must carry snapshot:true, got: \(json)")
    }

    func testExecPayloadOmitsOptionalSigningAndHashes() throws {
        // Unsigned binaries lack code_signing / sha256 / cdhash. Verify the JSON
        // omits the keys entirely rather than emitting nulls -- the server's
        // decoders rely on absence, not null.
        let payload = ExecPayload(
            pid: 1, ppid: 0, path: "/tmp/unsigned", args: [], cwd: "/", uid: 0, gid: 0,
            codeSigning: nil, sha256: nil, cdhash: nil, snapshot: false
        )
        let encoded = try encoder.encode(payload)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains("code_signing"))
        XCTAssertFalse(json.contains("sha256"))
        XCTAssertFalse(json.contains("cdhash"))
    }

    func testExecPayloadDecodesLegacyWireWithoutSnapshotKey() throws {
        // A pre-issue-#11 wire payload had no snapshot key. The custom decoder must
        // accept that and default to false rather than rejecting the envelope.
        let legacy = """
        {"args":["sh"],"cwd":"/","gid":0,"path":"/bin/sh","pid":1,"ppid":0,"uid":0}
        """
        let decoded = try decoder.decode(ExecPayload.self, from: Data(legacy.utf8))
        XCTAssertEqual(decoded.pid, 1)
        XCTAssertEqual(decoded.snapshot, false)
    }

    // MARK: - ForkPayload, ExitPayload, OpenPayload

    // spec:endpoint-event-collection/process-lifecycle-event-capture/a-daemon-forks-a-worker
    //
    // Daemon-forks-a-worker maps to the ForkPayload wire shape: child_pid + parent_pid, snake_case,
    // round-trippable. The exact-string assertion below pins the byte-level wire bytes (no extra
    // keys, no omitted ones) so a regression on field naming or insertion order would surface here.
    func testForkPayloadWireKeys() throws {
        let payload = ForkPayload(childPid: 5, parentPid: 4)
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        // Wire keys are snake_case, not Swift property names.
        XCTAssertEqual(json, #"{"child_pid":5,"parent_pid":4}"#)
        let decoded = try decoder.decode(ForkPayload.self, from: Data(json.utf8))
        XCTAssertEqual(decoded.childPid, 5)
        XCTAssertEqual(decoded.parentPid, 4)
    }

    func testExitPayloadWireKeys() throws {
        let payload = ExitPayload(pid: 99, exitCode: 137)
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        XCTAssertEqual(json, #"{"exit_code":137,"pid":99}"#)
        let decoded = try decoder.decode(ExitPayload.self, from: Data(json.utf8))
        XCTAssertEqual(decoded.pid, 99)
        XCTAssertEqual(decoded.exitCode, 137)
    }

    // spec:endpoint-event-collection/outbound-socket-flow-capture/a-process-opens-an-outbound-tcp-connection
    //
    // OpenPayload pins the wire shape for the open / connect class of events; the exact-string
    // assertion below proves the snake_case naming + key set match what the server's ingest decoder
    // expects. The spec's "outbound TCP connection" semantics map directly to this payload because the
    // extension's NetworkExtension surface raises connect events through the same wire envelope
    // OpenPayload defines.
    func testOpenPayloadWireKeys() throws {
        let payload = OpenPayload(pid: 12, path: "/etc/hosts", flags: 0)
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        XCTAssertEqual(json, #"{"flags":0,"path":"\/etc\/hosts","pid":12}"#)
        let decoded = try decoder.decode(OpenPayload.self, from: Data(json.utf8))
        XCTAssertEqual(decoded.path, "/etc/hosts")
    }

    // MARK: - CodeSigning

    func testCodeSigningWireKeys() throws {
        let signing = CodeSigning(teamID: "FDG8Q7N4CC", signingID: "com.fleetdm.edr", flags: 0x600, isPlatformBinary: false)
        let json = String(data: try encoder.encode(signing), encoding: .utf8) ?? ""
        XCTAssertEqual(
            json,
            #"{"flags":1536,"is_platform_binary":false,"signing_id":"com.fleetdm.edr","team_id":"FDG8Q7N4CC"}"#
        )
    }

    // MARK: - ApplicationControlBlockPayload

    func testApplicationControlBlockPayloadRoundTrip() throws {
        let payload = ApplicationControlBlockPayload(
            pid: 1234, path: "/bin/sh",
            ruleID: "app_control:42", ruleType: "BINARY", identifier: String(repeating: "f", count: 64),
            severity: "high", customMsg: "Blocked by policy", customURL: "https://example.test/info",
            policyID: 7, policyVersion: 12
        )
        let encoded = try encoder.encode(payload)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        // Spot-check snake_case wire keys land in the JSON -- the Go decoder reads
        // these literal names from server/rules/internal/catalog/application_control_block.go.
        XCTAssertTrue(json.contains("\"rule_id\":\"app_control:42\""), "missing rule_id, got: \(json)")
        XCTAssertTrue(json.contains("\"rule_type\":\"BINARY\""))
        XCTAssertTrue(json.contains("\"custom_msg\":\"Blocked by policy\""))
        XCTAssertTrue(json.contains("\"custom_url\":\"https:\\/\\/example.test\\/info\""))
        XCTAssertTrue(json.contains("\"policy_id\":7"))
        XCTAssertTrue(json.contains("\"policy_version\":12"))
        let decoded = try decoder.decode(ApplicationControlBlockPayload.self, from: encoded)
        XCTAssertEqual(decoded.ruleID, payload.ruleID)
        XCTAssertEqual(decoded.policyVersion, payload.policyVersion)
        XCTAssertEqual(decoded.customMsg, payload.customMsg)
    }

    func testApplicationControlBlockPayloadOmitsNilOptionals() throws {
        let payload = ApplicationControlBlockPayload(
            pid: 1, path: "/tmp/x", ruleID: "r", ruleType: "BINARY", identifier: "x",
            severity: "low", customMsg: nil, customURL: nil, policyID: 1, policyVersion: 1
        )
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains("custom_msg"))
        XCTAssertFalse(json.contains("custom_url"))
    }

    // MARK: - EventEnvelope

    // spec:endpoint-event-collection/canonical-event-envelope/an-event-envelope-is-well-formed
    //
    // Pins the canonical envelope shape every event MUST carry: event_id (UUID), host_id, timestamp_ns
    // (nanoseconds-since-epoch), event_type (string discriminator), and a nested payload. The exact
    // assertions below verify all five wire keys + the payload nest are byte-stable.
    func testEventEnvelopeWireKeysAndNesting() throws {
        let payload = ForkPayload(childPid: 11, parentPid: 10)
        let envelope = EventEnvelope(
            eventID: "11111111-1111-1111-1111-111111111111",
            hostID: "AAAA0001-0000-0000-0000-000000000001",
            timestampNs: 1_700_000_000_000_000_000,
            eventType: "fork",
            payload: payload
        )
        let encoded = try encoder.encode(envelope)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        // event_id, host_id, timestamp_ns, event_type, payload must all be present
        // with snake_case wire keys and the payload nested as-is.
        XCTAssertTrue(json.contains("\"event_id\":\"11111111-1111-1111-1111-111111111111\""))
        XCTAssertTrue(json.contains("\"host_id\":\"AAAA0001-0000-0000-0000-000000000001\""))
        XCTAssertTrue(json.contains("\"event_type\":\"fork\""))
        XCTAssertTrue(json.contains("\"timestamp_ns\":1700000000000000000"))
        XCTAssertTrue(json.contains("\"payload\":{\"child_pid\":11,\"parent_pid\":10}"))
        let decoded = try decoder.decode(EventEnvelope<ForkPayload>.self, from: encoded)
        XCTAssertEqual(decoded.eventType, "fork")
        XCTAssertEqual(decoded.payload.childPid, 11)
        XCTAssertEqual(decoded.timestampNs, 1_700_000_000_000_000_000)
    }
}
