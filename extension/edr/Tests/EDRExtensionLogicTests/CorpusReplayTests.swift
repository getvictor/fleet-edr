// Captured ESF event-envelope corpus replay.
//
// `extension/edr/Tests/corpus/<macOS-version>/<scenario>/*.json` holds wire-shape goldens for the
// envelopes the system extension emits via EventSerializer. This harness walks every golden file,
// peeks at its `event_type`, decodes it via the matching typed `EventEnvelope<P>`, re-encodes via
// the production `.sortedKeys` JSONEncoder, and asserts the bytes are byte-stable. The harness is
// the wire-format gate: a rename in `CodingKeys`, a change in encoder options, or a flip in an
// optional field's encode-when policy will land as a red test instead of a silent change shipped to
// agents in the field.
//
// Add a new corpus file by appending a `(filename, seeder)` pair to `seeds` below and running with
// EDR_CORPUS_REGENERATE=1. Update the wire format intentionally by editing a seeder (or a payload
// struct) and running the same regen flow, then committing the source change + the corpus diff in
// the same PR. The regen flow rewrites the baseline scenario directory; scenario directories
// holding real VM captures are not touched.

import Foundation
@testable import EDRExtensionLogic
import XCTest

/// CorpusEventHeader peeks at `event_type` so the harness can dispatch to the right
/// `EventEnvelope<P>` specialization. Declared at file scope (not nested in CorpusReplayTests)
/// to keep the CodingKeys enum at swiftlint's `nesting` depth limit; the type is `private` at file scope
/// so nothing outside this test file can see it.
private struct CorpusEventHeader: Decodable {
    let eventType: String
    enum CodingKeys: String, CodingKey {
        case eventType = "event_type"
    }
}

final class CorpusReplayTests: XCTestCase {
    // MARK: Constants

    /// Sentinel host_id used in every corpus envelope so the goldens are deterministic. Production
    /// envelopes carry the real IOPlatformUUID; the corpus deliberately uses a fixed sentinel so
    /// the wire-shape assertion does not depend on the test runner's hardware UUID.
    private static let sentinelHostID = "AAAAAAAA-0000-0000-0000-000000000000"

    /// Sentinel timestamp_ns (2023-11-14 00:00:00 UTC in nanoseconds). Same rationale as
    /// sentinelHostID: pin a stable value so the wire-shape assertion does not depend on wall-clock
    /// time at the moment of capture.
    private static let sentinelTimestampNs: UInt64 = 1_700_000_000_000_000_000

    /// Major macOS version directory the baseline seeders write under. Bump or add directories
    /// when a new release surfaces new ES fields the corpus needs to cover. The harness walks
    /// EVERY macOS-version directory at verify time so multiple versions are exercised together.
    private static let macOSVersionDir = "macOS-26"

    /// Scenario name. Tens of these will eventually exist (attack-curl-bash-pipe,
    /// noisy-spotlight, real-VM captures, etc.); the M8 starter set lives under "baseline".
    private static let scenarioDir = "baseline"

    /// Canonical encoder. Mirrors the configuration EventSerializer uses in production
    /// (`outputFormatting = .sortedKeys`) so the re-encoded bytes match the on-disk goldens.
    private static let canonicalEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()

    // MARK: Seed catalog

    /// Each seed pairs a filename under the baseline scenario directory with a closure that emits
    /// the canonical bytes when EDR_CORPUS_REGENERATE=1. In the normal verify path, the test reads
    /// the bytes off disk and proves decode + re-encode is byte-stable. Order does not matter; the
    /// catalog is the source of truth for which baseline files exist.
    private static let seeds: [(file: String, encode: () throws -> Data)] = [
        ("exec.json", encodeExecLive),
        ("exec-with-signing.json", encodeExecWithSigning),
        ("exec-snapshot.json", encodeExecSnapshot),
        ("fork.json", encodeFork),
        ("exit.json", encodeExit),
        ("open.json", encodeOpen),
        ("application_control_block.json", encodeApplicationControlBlock)
    ]

    // MARK: Test

    // spec:endpoint-event-collection/capture-is-non-fatal-on-individual-event-errors/one-event-fails-to-serialize
    //
    // The corpus replay is the structural guard that "capture is non-fatal on individual event
    // errors": every captured event in the corpus must round-trip byte-stable across encoder
    // versions. A regression that introduces a serialization error in any event type (say, exec
    // payload with new optional field) is caught here as a failure of THIS test, alerting the
    // operator to a wire-shape break. Note: the per-file loop uses `try`, so the FIRST round-trip
    // failure aborts the loop rather than continuing per-file; the spec's runtime "drop one bad
    // event, log, and continue" contract for the capture pipeline is implemented in the extension's
    // event-emission code, not in this test. This test pins the upstream invariant (no event in the
    // corpus fails to round-trip) that the runtime tolerance relies on.
    func testEveryCorpusFileRoundTripsByteStable() throws {
        let regenerate = ProcessInfo.processInfo.environment["EDR_CORPUS_REGENERATE"] == "1"
        let corpusRoot = Self.corpusDirectory()
        let baselineDir = corpusRoot
            .appendingPathComponent(Self.macOSVersionDir, isDirectory: true)
            .appendingPathComponent(Self.scenarioDir, isDirectory: true)
        let fileManager = FileManager.default

        // Top-level sanity check: if the corpus directory has been deleted or moved, fail loudly
        // up front rather than letting the seed-driven loop emit one error per missing seed.
        // The seed-driven loop's per-file XCTFail still runs underneath; this just gives a single
        // clean diagnostic when the whole tree is gone.
        XCTAssertTrue(
            fileManager.fileExists(atPath: corpusRoot.path) || regenerate,
            "corpus root missing at \(corpusRoot.path) -- did the directory get deleted?"
        )

        if regenerate {
            // Clean slate for the baseline scenario so a removed seeder leaves no stale golden.
            // Only the baseline dir is wiped -- sibling scenario dirs holding real captures are
            // untouched.
            try? fileManager.removeItem(at: baselineDir)
            try fileManager.createDirectory(at: baselineDir, withIntermediateDirectories: true)
        }

        // Seed first if regenerating; in either mode the verify step below runs on whatever is on
        // disk, which means regen also catches "the seeder produces non-stable bytes" regressions.
        for seed in Self.seeds {
            let url = baselineDir.appendingPathComponent(seed.file)
            if regenerate {
                let bytes = try seed.encode()
                try bytes.write(to: url)
            }
            guard fileManager.fileExists(atPath: url.path) else {
                XCTFail("missing corpus file: \(url.path) -- run EDR_CORPUS_REGENERATE=1 swift test to seed")
                continue
            }
            try assertRoundTripStable(at: url)
        }

        // Walk EVERY *.json under the corpus root (across macOS versions and scenarios) so
        // captured corpora that arrive in follow-up PRs are exercised as soon as they land, with
        // no harness change required.
        try assertEveryGoldenRoundTrips(rootedAt: corpusRoot, skipping: baselineDir)
    }

    // MARK: Helpers

    private func assertEveryGoldenRoundTrips(rootedAt root: URL, skipping skipDir: URL) throws {
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return
        }
        guard let enumerator = fileManager.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]) else {
            return
        }
        // Append a path separator so the prefix check matches the directory boundary exactly.
        // Without it, a hand-curated sibling scenario whose name starts with the same characters
        // (`baseline-extended/`, `baseline2/`) would be silently skipped and the wire-shape
        // gate would go quiet on that data without anyone noticing.
        let skipBase = skipDir.standardizedFileURL.path
        let skipPrefix = skipBase.hasSuffix("/") ? skipBase : skipBase + "/"
        for case let url as URL in enumerator {
            guard url.pathExtension == "json" else { continue }
            // The baseline directory is already covered by the seed-driven loop in the main test;
            // walking it twice would only burn cycles.
            if url.standardizedFileURL.path.hasPrefix(skipPrefix) { continue }
            try assertRoundTripStable(at: url)
        }
    }

    private func assertRoundTripStable(at url: URL) throws {
        let bytes = try Data(contentsOf: url)
        let header = try JSONDecoder().decode(CorpusEventHeader.self, from: bytes)
        let reencoded = try roundTrip(eventType: header.eventType, bytes: bytes)
        // Compare UTF-8 strings rather than raw Data: XCTest renders a Data mismatch as opaque
        // hex dumps, but the wire bytes are by construction UTF-8 JSON, so comparing strings
        // produces a readable diff that points at the exact field or formatting change that
        // caused the drift.
        XCTAssertEqual(
            String(data: reencoded, encoding: .utf8),
            String(data: bytes, encoding: .utf8),
            "corpus drift at \(url.lastPathComponent)"
        )
    }

    /// roundTrip dispatches on event_type because EventEnvelope is generic over payload type and
    /// Swift cannot pick the right specialization from the JSON itself. Adding a new event_type
    /// to production wire shape MUST also add a case here; the default branch fails so the gap is
    /// loud rather than silently uncovered.
    private func roundTrip(eventType: String, bytes: Data) throws -> Data {
        let decoder = JSONDecoder()
        let encoder = Self.canonicalEncoder
        switch eventType {
        case "exec":
            return try encoder.encode(decoder.decode(EventEnvelope<ExecPayload>.self, from: bytes))
        case "fork":
            return try encoder.encode(decoder.decode(EventEnvelope<ForkPayload>.self, from: bytes))
        case "exit":
            return try encoder.encode(decoder.decode(EventEnvelope<ExitPayload>.self, from: bytes))
        case "open":
            return try encoder.encode(decoder.decode(EventEnvelope<OpenPayload>.self, from: bytes))
        case "application_control_block":
            return try encoder.encode(decoder.decode(EventEnvelope<ApplicationControlBlockPayload>.self, from: bytes))
        default:
            XCTFail("unknown event_type in corpus: \(eventType) -- extend roundTrip(eventType:bytes:)")
            return Data()
        }
    }

    /// corpusDirectory locates `extension/edr/Tests/corpus/` via #filePath, which is the absolute
    /// path of THIS source file at compile time. Two .deletingLastPathComponent() calls walk up
    /// from `.../Tests/EDRExtensionLogicTests/CorpusReplayTests.swift` to `.../Tests/`, then we
    /// append `corpus/`. Works in both local dev (`$REPO/extension/edr/...`) and CI
    /// (`/Users/runner/work/fleet-edr/fleet-edr/extension/edr/...`) because #filePath is baked at
    /// compile time and CI compiles from a checkout of the same source tree -- the SwiftPM
    /// resources/bundle path would not work here because Tests/corpus/ sits OUTSIDE the test
    /// target's source root.
    private static func corpusDirectory() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("corpus", isDirectory: true)
    }

    // MARK: Seed encoders

    private static func encodeEnvelope<P: Codable & Sendable>(
        eventID: String,
        eventType: String,
        payload: P
    ) throws -> Data {
        let envelope = EventEnvelope(
            eventID: eventID,
            hostID: sentinelHostID,
            timestampNs: sentinelTimestampNs,
            eventType: eventType,
            payload: payload
        )
        return try canonicalEncoder.encode(envelope)
    }

    /// Live exec of an unsigned shell -- no code_signing, no sha256, no cdhash. Snapshot key
    /// MUST be absent on the wire (the encoder omits snapshot=false for live execs); covers the
    /// "minimal payload, optional fields all nil" shape.
    private static func encodeExecLive() throws -> Data {
        let payload = ExecPayload(
            pid: 4242, ppid: 1, path: "/bin/sh",
            args: ["sh", "-c", "echo hello"],
            cwd: "/Users/test", uid: 501, gid: 20,
            codeSigning: nil,
            sha256: nil,
            cdhash: nil,
            snapshot: false
        )
        return try encodeEnvelope(
            eventID: "11111111-1111-1111-1111-111111111111",
            eventType: "exec",
            payload: payload
        )
    }

    /// Live exec with the full signing block + sha256 + cdhash populated. Covers the "all optional
    /// fields present" shape and pins the snake_case wire keys on the nested CodeSigning object
    /// (team_id, signing_id, is_platform_binary).
    private static func encodeExecWithSigning() throws -> Data {
        let signing = CodeSigning(
            teamID: "FDG8Q7N4CC",
            signingID: "com.apple.bash",
            flags: 0x2000,
            isPlatformBinary: true
        )
        let payload = ExecPayload(
            pid: 4243, ppid: 1, path: "/bin/bash",
            args: ["bash", "-l"],
            cwd: "/Users/test", uid: 501, gid: 20,
            codeSigning: signing,
            sha256: String(repeating: "a", count: 64),
            cdhash: String(repeating: "b", count: 40),
            snapshot: false
        )
        return try encodeEnvelope(
            eventID: "22222222-2222-2222-2222-222222222222",
            eventType: "exec",
            payload: payload
        )
    }

    /// Startup-snapshot exec. The encoder emits `"snapshot":true` only when the field is true so
    /// this golden pins the difference from the live-exec wire shape -- the server's detection
    /// engine relies on the `bytes.Contains(`"snapshot":true`)` gate to skip pre-existing processes.
    private static func encodeExecSnapshot() throws -> Data {
        let payload = ExecPayload(
            pid: 99, ppid: 1, path: "/usr/sbin/cron",
            args: ["cron"],
            cwd: "/", uid: 0, gid: 0,
            codeSigning: nil, sha256: nil, cdhash: nil,
            snapshot: true
        )
        return try encodeEnvelope(
            eventID: "33333333-3333-3333-3333-333333333333",
            eventType: "exec",
            payload: payload
        )
    }

    private static func encodeFork() throws -> Data {
        let payload = ForkPayload(childPid: 5000, parentPid: 4242)
        return try encodeEnvelope(
            eventID: "44444444-4444-4444-4444-444444444444",
            eventType: "fork",
            payload: payload
        )
    }

    private static func encodeExit() throws -> Data {
        let payload = ExitPayload(pid: 5000, exitCode: 0)
        return try encodeEnvelope(
            eventID: "55555555-5555-5555-5555-555555555555",
            eventType: "exit",
            payload: payload
        )
    }

    private static func encodeOpen() throws -> Data {
        let payload = OpenPayload(pid: 4242, path: "/etc/hosts", flags: 0)
        return try encodeEnvelope(
            eventID: "66666666-6666-6666-6666-666666666666",
            eventType: "open",
            payload: payload
        )
    }

    private static func encodeApplicationControlBlock() throws -> Data {
        let payload = ApplicationControlBlockPayload(
            pid: 4242, path: "/tmp/blocked",
            ruleID: "app_control:42",
            ruleType: "BINARY",
            identifier: String(repeating: "f", count: 64),
            severity: "high",
            customMsg: "Blocked by policy",
            customURL: "https://example.test/info",
            policyID: 7,
            policyVersion: 12
        )
        return try encodeEnvelope(
            eventID: "77777777-7777-7777-7777-777777777777",
            eventType: "application_control_block",
            payload: payload
        )
    }
}
