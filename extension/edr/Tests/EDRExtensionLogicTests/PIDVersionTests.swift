// PR 2 of the flow-process-identity change (issue #403): the device emits the kernel PID generation (pidversion) on the
// exec / fork / network_connect / dns_query payloads so the server can correlate a flow to the exact process generation by
// identity rather than a fork-to-exit time window. These tests pin (a) extractProcessInfo returns pidversion from a flow's
// audit token (nil when the token is absent), and (b) the exec/fork payload encoders emit `pidversion` when present and OMIT
// the key when nil, keeping the legacy wire shape unchanged for agents that do not carry it.
//
// NetworkConnectPayload / DNSQueryPayload live in networkextension/NetworkEventSerializer.swift, which is not part of this
// SwiftPM logic module (it redeclares EventEnvelope, which would collide with the system-extension serializer's copy), so
// their encoding is exercised end-to-end on the VM rather than here.

import Darwin
import Foundation
@testable import EDRExtensionLogic
import XCTest

final class PIDVersionTests: XCTestCase {
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()

    private let decoder = JSONDecoder()

    // MARK: extractProcessInfo

    // A flow that carries an audit token yields a non-nil pidversion (the identity the server joins on), matching the token's
    // own accessors. pidversion read from the same token as pid/uid keeps the triple internally consistent (issue #403).
    func testExtractProcessInfoReturnsPidVersionFromToken() {
        // Distinct values in every slot so a wrong field selection would surface. The accessors (audit_token_to_pid / _euid /
        // _pidversion) define which slot each maps to; the assertions compare extractProcessInfo against those same accessors,
        // so this verifies the Data-to-token parsing and that pidversion is returned, without hardcoding slot indices.
        let token = audit_token_t(val: (10, 501, 20, 30, 40, 4242, 60, 99))
        let data = withUnsafeBytes(of: token) { Data($0) }

        let info = extractProcessInfo(from: data)

        XCTAssertEqual(info.pid, audit_token_to_pid(token))
        XCTAssertEqual(info.uid, audit_token_to_euid(token))
        XCTAssertNotNil(info.pidversion, "a present audit token must yield a pidversion")
        XCTAssertEqual(info.pidversion, UInt32(bitPattern: audit_token_to_pidversion(token)))
    }

    // No audit token (the deferred proxied-flow case, or a flow the system could not attribute) yields a nil pidversion so the
    // server falls back to its event-time window join, and a sentinel pid of -1.
    func testExtractProcessInfoNilTokenYieldsNilPidVersion() {
        let info = extractProcessInfo(from: nil)
        XCTAssertEqual(info.pid, -1)
        XCTAssertNil(info.pidversion, "an absent token must yield nil pidversion (server uses the time-window fallback)")
    }

    // A too-short blob (not a full audit_token_t) must not crash and must leave pidversion nil.
    func testExtractProcessInfoShortBlobYieldsNilPidVersion() {
        let info = extractProcessInfo(from: Data([0x01, 0x02, 0x03]))
        XCTAssertNil(info.pidversion)
    }

    // MARK: ExecPayload

    // spec:endpoint-event-collection/process-lifecycle-event-capture/a-user-runs-a-shell-command
    //
    // A live exec carries pidversion; the wire key is the snake_case `pidversion` the server decodes, and the value round-trips.
    func testExecPayloadEmitsPidVersionWhenPresent() throws {
        let payload = ExecPayload(
            pid: 4242, ppid: 1, path: "/bin/bash", args: ["bash"], cwd: "", uid: 501, gid: 20,
            codeSigning: nil, sha256: nil, cdhash: nil, pidVersion: 99
        )
        let encoded = try encoder.encode(payload)
        let json = String(decoding: encoded, as: UTF8.self)
        XCTAssertTrue(json.contains("\"pidversion\":99"), "exec payload must emit pidversion when set; got \(json)")
        let decoded = try decoder.decode(ExecPayload.self, from: encoded)
        XCTAssertEqual(decoded.pidVersion, 99)
    }

    // An exec without pidversion (e.g. a startup snapshot row) OMITS the key, so the wire shape is byte-identical to a
    // pre-#403 agent and the server stores NULL.
    func testExecPayloadOmitsPidVersionWhenNil() throws {
        let payload = ExecPayload(
            pid: 4242, ppid: 1, path: "/bin/bash", args: ["bash"], cwd: "", uid: 501, gid: 20,
            codeSigning: nil, sha256: nil, cdhash: nil, pidVersion: nil
        )
        let json = String(decoding: try encoder.encode(payload), as: UTF8.self)
        XCTAssertFalse(json.contains("pidversion"), "exec payload must omit pidversion when nil; got \(json)")
    }

    // MARK: ForkPayload

    // spec:endpoint-event-collection/process-lifecycle-event-capture/a-daemon-forks-a-worker
    //
    // A fork carries the child's pidversion under the snake_case wire key; nil omits it.
    func testForkPayloadPidVersionPresentAndOmitted() throws {
        let withVersion = try encoder.encode(ForkPayload(childPid: 10, parentPid: 1, pidVersion: 7))
        let withJSON = String(decoding: withVersion, as: UTF8.self)
        XCTAssertTrue(withJSON.contains("\"pidversion\":7"), "fork payload must emit child pidversion; got \(withJSON)")
        XCTAssertEqual(try decoder.decode(ForkPayload.self, from: withVersion).pidVersion, 7)

        let withoutJSON = String(decoding: try encoder.encode(ForkPayload(childPid: 10, parentPid: 1, pidVersion: nil)), as: UTF8.self)
        XCTAssertFalse(withoutJSON.contains("pidversion"), "fork payload must omit pidversion when nil; got \(withoutJSON)")
    }
}
