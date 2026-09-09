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

    // MARK: ExecPayload

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

    // spec:endpoint-event-collection/reconciliation-events-are-tagged/extension-restarts-and-rebuilds-the-live-process-set
    //
    // The spec scenario asserts the extension emits one exec event per pre-existing process with
    // snapshot = true on restart. The enumeration side lives in ProcessSnapshotEnumerator.swift (kept out of
    // the SwiftPM target because it invokes sysctl against the live process table on the test machine, which
    // makes machine-dependent assertions impossible). The wire-shape side, which is the contract the server's
    // detection engine consumes, is exactly what this test pins: an ExecPayload constructed with `snapshot:
    // true` serializes with `"snapshot":true` in the wire bytes so server/detection's `bytes.Contains` gate
    // over `"snapshot":true` drops snapshot-originated execs from rule evaluation.
    func testExecPayloadEmitsSnapshotKeyWhenTrue() throws {
        let payload = ExecPayload(
            pid: 99, ppid: 1, path: "/bin/ls", args: ["ls"], cwd: "/", uid: 0, gid: 0,
            codeSigning: nil, sha256: nil, cdhash: nil, snapshot: true
        )
        let encoded = try encoder.encode(payload)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"snapshot\":true"), "startup-snapshot exec must carry snapshot:true, got: \(json)")
    }

    // spec:endpoint-event-collection/launch-item-registration-event-capture/a-launchdaemon-is-registered-via-background-task-management
    func testBtmLaunchItemAddPayloadRoundTripAndWireKeys() throws {
        // Pins the snake_case wire keys the Go privilege_launchd_plist_write rule consumes. Models the real ground-truth:
        // the DECISION input is executable_code_signing (here an unsigned dropper, which fires),
        // while the instigator is Apple's smd (a platform binary) and is forensic-only.
        let payload = BtmLaunchItemAddPayload(
            itemType: "daemon",
            itemPath: "/Library/LaunchDaemons/com.evil.persistence.plist",
            executablePath: "/tmp/dropper",
            legacy: true,
            managed: false,
            uid: 0,
            executableCodeSigning: CodeSigning(teamID: "", signingID: "", flags: 0, isPlatformBinary: false),
            instigatorPid: 93,
            instigatorCodeSigning: CodeSigning(teamID: "", signingID: "com.apple.xpc.smd", flags: 0, isPlatformBinary: true)
        )
        let encoded = try encoder.encode(payload)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        for key in ["\"item_type\":\"daemon\"", "\"item_path\":", "\"executable_path\":",
                    "\"managed\":false", "\"executable_code_signing\":", "\"instigator_pid\":93",
                    "\"instigator_code_signing\":", "\"is_platform_binary\":false"] {
            XCTAssertTrue(json.contains(key), "missing wire key \(key) in: \(json)")
        }
        let decoded = try decoder.decode(BtmLaunchItemAddPayload.self, from: encoded)
        XCTAssertEqual(decoded.itemType, payload.itemType)
        XCTAssertEqual(decoded.itemPath, payload.itemPath)
        XCTAssertEqual(decoded.executablePath, payload.executablePath)
        XCTAssertEqual(decoded.legacy, payload.legacy)
        XCTAssertEqual(decoded.managed, payload.managed)
        XCTAssertEqual(decoded.uid, payload.uid)
        XCTAssertEqual(decoded.executableCodeSigning?.isPlatformBinary, false, "unsigned executable -> decision input fires")
        XCTAssertEqual(decoded.instigatorPid, payload.instigatorPid)
        XCTAssertEqual(decoded.instigatorCodeSigning?.isPlatformBinary, true, "instigator smd is platform; forensic only")
    }

    func testExecPayloadOmitsOptionalSigningAndHashes() throws {
        // Unsigned binaries lack code_signing / sha256 / cdhash. Verify the JSON
        // omits the keys entirely rather than emitting nulls; the server's
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

    // spec:endpoint-event-collection/process-lifecycle-event-capture/the-exec-event-carries-cdhash-only-when-the-kernel-reported-one
    //
    // Two of the scenario's three cases: a Hardened Runtime binary whose kernel reported a hash carries it, and a
    // non-hardened binary omits it. The third, a HARDENED binary whose reported hash is all zeros, cannot be reached
    // from here at all, because this test constructs ExecPayload directly and so can pair the runtime flag with any
    // hash it likes. testCDHashHexStringRejectsAnAllZeroKernelValue below covers that one against the real helper.
    // The condition is therefore NOT "present iff hardened": it is present only when the process is hardened AND the
    // kernel reported a usable hash.
    //
    // Both cases live in one test because a test of only the present half would pass against a serializer that emitted
    // a placeholder for every exec, and that placeholder is the failure that matters. The kernel maps pages lazily on
    // a non-hardened process and does not re-verify them after load, so a cdhash reported for one is not the identity
    // of the bytes that will run; emitting it anyway would give a signature-based exclusion a value it must not trust.
    //
    // Asserted on the wire bytes, not the decoded struct: the server reads `cdhash` by that literal name, and absence
    // rather than null is what its decoder relies on.
    func testExecPayloadCarriesCDHashOnlyForHardenedBinaries() throws {
        let hardened = ExecPayload(
            pid: 501, ppid: 1, path: "/usr/bin/ssh", args: ["ssh"], cwd: "/", uid: 0, gid: 0,
            codeSigning: CodeSigning(teamID: "", signingID: "com.apple.ssh", flags: 0x10000, isPlatformBinary: true),
            sha256: nil, cdhash: String(repeating: "c", count: 40), snapshot: false
        )
        let hardenedJSON = String(data: try encoder.encode(hardened), encoding: .utf8) ?? ""
        XCTAssertEqual(
            hardenedJSON,
            "{\"args\":[\"ssh\"],\"cdhash\":\"cccccccccccccccccccccccccccccccccccccccc\",\"code_signing\":{\"flags\":65536," +
            "\"is_platform_binary\":true,\"signing_id\":\"com.apple.ssh\",\"team_id\":\"\"}," +
                "\"cwd\":\"\\/\",\"gid\":0,\"path\":\"\\/usr\\/bin\\/ssh\",\"pid\":501,\"ppid\":1,\"uid\":0}"
        )

        let notHardened = ExecPayload(
            pid: 502, ppid: 1, path: "/usr/local/bin/tool", args: ["tool"], cwd: "/", uid: 0, gid: 0,
            codeSigning: CodeSigning(teamID: "FDG8Q7N4CC", signingID: "com.example.tool", flags: 0, isPlatformBinary: false),
            sha256: nil, cdhash: nil, snapshot: false
        )
        let notHardenedJSON = String(data: try encoder.encode(notHardened), encoding: .utf8) ?? ""
        XCTAssertEqual(
            notHardenedJSON,
            "{\"args\":[\"tool\"],\"code_signing\":{\"flags\":0,\"is_platform_binary\":false," +
            "\"signing_id\":\"com.example.tool\",\"team_id\":\"FDG8Q7N4CC\"}," +
                "\"cwd\":\"\\/\",\"gid\":0,\"path\":\"\\/usr\\/local\\/bin\\/tool\",\"pid\":502,\"ppid\":1," +
                "\"uid\":0}"
        )
        XCTAssertFalse(notHardenedJSON.contains("cdhash"), "the key is absent, not null")
    }

    // spec:endpoint-event-collection/process-lifecycle-event-capture/the-exec-event-carries-cdhash-only-when-the-kernel-reported-one
    //
    // The third case, and the one the payload-level test above cannot reach: a HARDENED process whose kernel cdhash is all zeros.
    // cdhashHexString returns nil for it, so the event omits the field exactly as it does for a non-hardened binary, and the
    // requirement is not the biconditional "hardened iff present" it first appeared to be.
    //
    // This branch had no test at all before now, which is why the gap survived: the payload tests construct ExecPayload directly
    // and so can pair the Hardened Runtime flag with any hash the author likes, including one the kernel would never report.
    // Emitting the zeros instead would be worse than omitting them, because a CDHASH rule whose identifier is forty zeros would
    // then match every such exec by coincidence.
    // The 20-element tuple is the C surface (es_process_t.cdhash imports as a fixed-size tuple), so the same scoped
    // disable/enable pair CDHashHex.swift carries around its own signature applies to these two locals.
    // swiftlint:disable large_tuple
    func testCDHashHexStringRejectsAnAllZeroKernelValue() {
        let allZero: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                      UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) =
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        XCTAssertNil(cdhashHexString(from: allZero), "an all-zero kernel cdhash means the kernel has none")

        // One non-zero byte in the LAST position: an implementation that checked only the first byte, or only a prefix, would
        // wrongly reject this real hash and silently drop cdhash from every event carrying one shaped like it.
        let lastByteSet: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                          UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) =
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        XCTAssertEqual(cdhashHexString(from: lastByteSet), "0000000000000000000000000000000000000001")
    }
    // swiftlint:enable large_tuple

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

    // MARK: ForkPayload, ExitPayload, OpenPayload

    // spec:endpoint-event-collection/process-lifecycle-event-capture/a-daemon-forks-a-worker
    //
    // Daemon-forks-a-worker maps to the ForkPayload wire shape: child_pid + parent_pid, snake_case,
    // round-trippable. The encoder is configured with .sortedKeys (see the encoder block at the top
    // of this file) so the exact-string assertion below pins the sorted-key JSON output: a regression
    // on field naming, omitting a key, or adding an unexpected one would surface here as the
    // assertion comparing against a literal byte string.
    func testForkPayloadWireKeys() throws {
        let payload = ForkPayload(childPid: 5, parentPid: 4, pidVersion: nil)
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

    // The outbound-TCP-connection marker was considered for this test and pulled: OpenPayload is the
    // ESF FILE-OPEN event shape (pid + file path + flags, see EventSerializer.swift), NOT an outbound
    // network connection. The outbound-tcp-connection scenario is served by NetworkConnectPayload in
    // extension/edr/networkextension/NetworkEventSerializer.swift; that surface has no unit-test
    // target today, tracked in #259.
    func testOpenPayloadWireKeys() throws {
        let payload = OpenPayload(pid: 12, path: "/etc/hosts", flags: 0)
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        XCTAssertEqual(json, #"{"flags":0,"path":"\/etc\/hosts","pid":12}"#)
        let decoded = try decoder.decode(OpenPayload.self, from: Data(json.utf8))
        XCTAssertEqual(decoded.path, "/etc/hosts")
    }

    // MARK: CodeSigning

    func testCodeSigningWireKeys() throws {
        let signing = CodeSigning(teamID: "FDG8Q7N4CC", signingID: "com.fleetdm.edr", flags: 0x600, isPlatformBinary: false)
        let json = String(data: try encoder.encode(signing), encoding: .utf8) ?? ""
        XCTAssertEqual(
            json,
            #"{"flags":1536,"is_platform_binary":false,"signing_id":"com.fleetdm.edr","team_id":"FDG8Q7N4CC"}"#
        )
    }

    // MARK: ApplicationControlBlockPayload

    func testApplicationControlBlockPayloadRoundTrip() throws {
        let payload = ApplicationControlBlockPayload(
            pid: 1234, path: "/bin/sh",
            ruleID: "app_control:42", ruleType: "BINARY", identifier: String(repeating: "f", count: 64),
            severity: "high", customMsg: "Blocked by policy", customURL: "https://example.test/info",
            policyID: 7, policyVersion: 12
        )
        let encoded = try encoder.encode(payload)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        // Spot-check snake_case wire keys land in the JSON; the Go decoder reads
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

    // spec:extension-application-control/block-event-emission/a-block-emits-a-block-event-whose-identifier-is-the-matched-value
    //
    // Runs the real decision and builds the payload from what it returned, rather than hand-writing the fields, so the
    // wire assertions are made against values the decider actually produced.
    //
    // What this cannot distinguish, and the requirement's "not the rule's own stored identifier" clause can: today every
    // layer is a map keyed by `rule.identifier`, so a match always returns a value equal to it. The clause is a
    // constraint on future divergence (a case-folded or glob-matched layer would break the equality), and it matches the
    // code, since emitBlockEvent is handed the matched identifier and not the rule. No test can separate the two while
    // the maps are keyed this way; asserting otherwise here would be a test that cannot fail dressed as one that can.
    //
    // The marker previously sat on a decideAuthExec test that emits no event at all. The ESF glue in emitBlockEvent
    // (audit token to pid, es_token to path) needs an es_message_t and stays at the system / VM layer; the mapping
    // from decision to wire shape is the part that is unit-testable, and it is where the field names live.
    func testBlockPayloadCarriesTheMatchedIdentifierNotTheRuleIdentifier() throws {
        let rule = makeRule(ruleType: ApplicationControlRuleType.teamID, identifier: "EQHXZ8M8AV")
        let decision = decideAuthExec(
            tuple: makeTuple(teamID: "EQHXZ8M8AV"),
            snapshot: makeSnapshot(teamIDRules: ["EQHXZ8M8AV": rule]),
            hashOutcome: .notNeeded
        )
        guard case let .deny(matchedRule, matchedIdentifier) = decision else {
            return XCTFail("a TEAMID BLOCK/PROTECT rule must deny, got \(decision)")
        }
        let payload = ApplicationControlBlockPayload(
            pid: 991, path: "/usr/local/bin/blocked",
            ruleID: matchedRule.ruleID, ruleType: matchedRule.ruleType, identifier: matchedIdentifier,
            severity: matchedRule.severity, customMsg: matchedRule.customMsg, customURL: matchedRule.customURL,
            policyID: 7, policyVersion: 12
        )
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        // One literal rather than a set of `contains` checks. The encoder uses .sortedKeys, so the bytes are deterministic, and
        // equality is the only assertion that fails when a field is ADDED. That is the direction this PR is about: the canonical
        // requirement claimed four fields (rule_identifier, matched_identifier, process, ancestry) the wire has never had, and a
        // substring test cannot notice an extra key. Absence assertions for those four follow, because a literal alone would not
        // say WHICH four the requirement invented if this ever regresses.
        XCTAssertEqual(
            json,
            "{\"identifier\":\"EQHXZ8M8AV\",\"path\":\"\\/usr\\/local\\/bin\\/blocked\",\"pid\":991," +
                "\"policy_id\":7,\"policy_version\":12,\"rule_id\":\"app_control:test-EQHXZ8M8AV\"," +
                "\"rule_type\":\"TEAMID\",\"severity\":\"medium\"}"
        )
        for absent in ["rule_identifier", "matched_identifier", "ancestry", "\"process\""] {
            XCTAssertFalse(json.contains(absent), "\(absent) is not a field of this event")
        }
    }

    // MARK: FileRenamePayload

    // spec:endpoint-event-collection/sensitive-path-file-modification-capture/a-rename-event-carries-both-of-its-paths
    //
    // The event's SHAPE, which is all this layer can reach: FileTamperSubscriber imports EndpointSecurity and so is outside
    // the SwiftPM logic target, which means the subscription and handleRename's reading of the rename union are NOT covered
    // here and are verified at the system / VM layer. Saying so rather than letting the marker imply otherwise, since this
    // test passes unchanged if RENAME is never subscribed at all.
    //
    // The wire shape the server's file_rename decoder reads. Pinned as a whole literal for the same reason the block event is:
    // a substring check cannot fail when a field is ADDED, and the server binds these two keys to Sigma's SourceFilename and
    // TargetFilename, so a rename or a swap here silently changes which path the detection judges.
    //
    // `source_path` and `path` rather than a symmetric pair of names: `path` is the DESTINATION, matching every other file
    // event's target field, which is what lets one detection ask the right question of both an open and a rename.
    func testFileRenamePayloadPinsItsWireShape() throws {
        let payload = FileRenamePayload(pid: 4242, sourcePath: "/tmp/staged", path: "/etc/sudoers.d/evil")
        let json = String(data: try encoder.encode(payload), encoding: .utf8) ?? ""
        XCTAssertEqual(
            json,
            "{\"path\":\"\\/etc\\/sudoers.d\\/evil\"," +
                "\"pid\":4242,\"source_path\":\"\\/tmp\\/staged\"}"
        )
        let decoded = try decoder.decode(FileRenamePayload.self, from: try encoder.encode(payload))
        XCTAssertEqual(decoded.sourcePath, "/tmp/staged")
        XCTAssertEqual(decoded.path, "/etc/sudoers.d/evil")
    }

    // MARK: Destruction payloads

    // spec:endpoint-event-collection/destruction-of-a-sensitive-file-is-captured/an-emptied-file-is-reported-as-a-truncation
    // spec:endpoint-event-collection/destruction-of-a-sensitive-file-is-captured/a-removed-file-is-reported-as-a-deletion
    //
    // The two destruction shapes, pinned as whole literals for the same reason the block event is: a substring check cannot
    // fail when a field is ADDED, and the server decodes these by literal key name.
    //
    // What this canNOT reach, said plainly rather than implied by the marker: whether the ESF client is subscribed, whether an
    // O_TRUNC open is told from a routine read, and whether a truncate syscall and a shell redirect both arrive. All of that
    // lives in FileTamperSubscriber, which imports EndpointSecurity and sits outside this target, and is verified at the VM
    // layer. These tests pass unchanged if none of it works.
    func testDestructionPayloadsPinTheirWireShapes() throws {
        let truncated = FileTruncatePayload(pid: 4242, path: "/etc/sudoers")
        XCTAssertEqual(
            String(data: try encoder.encode(truncated), encoding: .utf8) ?? "",
            "{\"path\":\"\\/etc\\/sudoers\",\"pid\":4242}"
        )

        let deleted = FileDeletePayload(pid: 4242, path: "/etc/sudoers.d/admins")
        XCTAssertEqual(
            String(data: try encoder.encode(deleted), encoding: .utf8) ?? "",
            "{\"path\":\"\\/etc\\/sudoers.d\\/admins\",\"pid\":4242}"
        )

        // The payloads are byte-identical for the same input, which is exactly why the EVENT TYPE has to carry the meaning:
        // an emptied file still exists and a removed one does not, and nothing in the payload says which happened.
        let sameInputTruncate = FileTruncatePayload(pid: 1, path: "/etc/sudoers")
        let sameInputDelete = FileDeletePayload(pid: 1, path: "/etc/sudoers")
        XCTAssertEqual(try encoder.encode(sameInputTruncate), try encoder.encode(sameInputDelete),
                       "if these ever diverge, the envelope's event_type is no longer the only discriminator")
    }

    // MARK: EventEnvelope

    // spec:endpoint-event-collection/canonical-event-envelope/an-event-envelope-is-well-formed
    //
    // Pins the canonical envelope shape every event MUST carry: event_id (UUID), host_id, timestamp_ns
    // (nanoseconds-since-epoch), event_type (string discriminator), and a nested payload. The substring
    // (json.contains) assertions below verify all five wire keys are present and the payload is nested
    // as a sub-object; a full byte-level comparison would also be valid given .sortedKeys but the
    // substring form is more diagnostic when one key changes name.
    func testEventEnvelopeWireKeysAndNesting() throws {
        let payload = ForkPayload(childPid: 11, parentPid: 10, pidVersion: nil)
        let envelope = EventEnvelope(
            eventID: "11111111-1111-1111-1111-111111111111",
            hostID: "AAAA0001-0000-0000-0000-000000000001",
            timestampNs: 1_700_000_000_000_000_000,
            eventType: "fork",
            platform: EventPlatform.macOS,
            payload: payload
        )
        let encoded = try encoder.encode(envelope)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        // event_id, host_id, timestamp_ns, event_type, platform, payload must all be present
        // with snake_case wire keys and the payload nested as-is.
        XCTAssertTrue(json.contains("\"event_id\":\"11111111-1111-1111-1111-111111111111\""))
        XCTAssertTrue(json.contains("\"host_id\":\"AAAA0001-0000-0000-0000-000000000001\""))
        XCTAssertTrue(json.contains("\"event_type\":\"fork\""))
        XCTAssertTrue(json.contains("\"platform\":\"darwin\""))
        XCTAssertTrue(json.contains("\"timestamp_ns\":1700000000000000000"))
        XCTAssertTrue(json.contains("\"payload\":{\"child_pid\":11,\"parent_pid\":10}"))
        let decoded = try decoder.decode(EventEnvelope<ForkPayload>.self, from: encoded)
        XCTAssertEqual(decoded.eventType, "fork")
        XCTAssertEqual(decoded.platform, "darwin")
        XCTAssertEqual(decoded.payload.childPid, 11)
        XCTAssertEqual(decoded.timestampNs, 1_700_000_000_000_000_000)
    }

    // spec:endpoint-event-collection/serialized-events-declare-their-platform/an-esf-event-envelope-carries-the-darwin-platform
    //
    // The serializer stamps platform=darwin on every envelope (ADR-0018). The server scopes detection rules by platform and surfaces
    // it in the hosts view; a macOS extension always declares darwin.
    func testEnvelopeStampsDarwinPlatform() throws {
        let serializer = EventSerializer()
        let data = try XCTUnwrap(serializer.serialize(eventType: "fork", payload: ForkPayload(childPid: 2, parentPid: 1, pidVersion: nil)))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(obj?["platform"] as? String, "darwin")
    }
}
