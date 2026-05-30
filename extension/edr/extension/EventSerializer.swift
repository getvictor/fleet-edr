import Foundation
import IOKit
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "EventSerializer")

// MARK: - Payload types

struct CodeSigning: Codable, Sendable {
    let teamID: String
    let signingID: String
    let flags: UInt32
    let isPlatformBinary: Bool

    enum CodingKeys: String, CodingKey {
        case teamID = "team_id"
        case signingID = "signing_id"
        case flags
        case isPlatformBinary = "is_platform_binary"
    }
}

struct ExecPayload: Codable, Sendable {
    let pid: pid_t
    let ppid: pid_t
    let path: String
    let args: [String]
    let cwd: String
    let uid: uid_t
    let gid: gid_t
    let codeSigning: CodeSigning?
    let sha256: String?
    /// 40-char lowercase hex of the binary's Code Directory hash. Populated only when the new process runs under Apple's
    /// Hardened Runtime (per Phase A close-out spec). Absent for unsigned binaries and signed-but-not-hardened binaries; the
    /// encoder below omits the key entirely in those cases so the wire shape stays compact and backwards-tolerant.
    let cdhash: String?
    /// True only for synthetic exec events emitted by the ESF startup snapshot pass
    /// (issue #11). The custom encoder below OMITS the key entirely when false, so
    /// the wire shape for live execs stays byte-identical to the pre-#11 format.
    /// Server-side detection rules drop snapshot=true events; the graph builder
    /// still materialises them so the process tree shows pre-existing processes
    /// after an extension restart.
    let snapshot: Bool

    enum CodingKeys: String, CodingKey {
        case pid, ppid, path, args, cwd, uid, gid
        case codeSigning = "code_signing"
        case sha256
        case cdhash
        case snapshot
    }

    init(
        pid: pid_t, ppid: pid_t, path: String, args: [String], cwd: String,
        uid: uid_t, gid: gid_t, codeSigning: CodeSigning?, sha256: String?,
        cdhash: String? = nil,
        snapshot: Bool = false
    ) {
        self.pid = pid
        self.ppid = ppid
        self.path = path
        self.args = args
        self.cwd = cwd
        self.uid = uid
        self.gid = gid
        self.codeSigning = codeSigning
        self.sha256 = sha256
        self.cdhash = cdhash
        self.snapshot = snapshot
    }

    // Custom decoder so a live exec payload (which the encoder OMITS the snapshot
    // key for, by design) round-trips correctly. Without this, Codable synthesis
    // would require the key and reject every live-exec payload on decode.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        pid = try container.decode(pid_t.self, forKey: .pid)
        ppid = try container.decode(pid_t.self, forKey: .ppid)
        path = try container.decode(String.self, forKey: .path)
        args = try container.decode([String].self, forKey: .args)
        cwd = try container.decode(String.self, forKey: .cwd)
        uid = try container.decode(uid_t.self, forKey: .uid)
        gid = try container.decode(gid_t.self, forKey: .gid)
        codeSigning = try container.decodeIfPresent(CodeSigning.self, forKey: .codeSigning)
        sha256 = try container.decodeIfPresent(String.self, forKey: .sha256)
        cdhash = try container.decodeIfPresent(String.self, forKey: .cdhash)
        snapshot = try container.decodeIfPresent(Bool.self, forKey: .snapshot) ?? false
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(pid, forKey: .pid)
        try container.encode(ppid, forKey: .ppid)
        try container.encode(path, forKey: .path)
        try container.encode(args, forKey: .args)
        try container.encode(cwd, forKey: .cwd)
        try container.encode(uid, forKey: .uid)
        try container.encode(gid, forKey: .gid)
        try container.encodeIfPresent(codeSigning, forKey: .codeSigning)
        try container.encodeIfPresent(sha256, forKey: .sha256)
        try container.encodeIfPresent(cdhash, forKey: .cdhash)
        // Only emit snapshot when true — keeps the live-exec wire shape stable
        // and avoids tripping the server detection-engine bytes.Contains gate
        // on a `"snapshot":false` payload (false events would correctly be
        // kept by the JSON probe, but we want zero wire change for live exec).
        if snapshot {
            try container.encode(true, forKey: .snapshot)
        }
    }
}

struct ForkPayload: Codable, Sendable {
    let childPid: pid_t
    let parentPid: pid_t

    enum CodingKeys: String, CodingKey {
        case childPid = "child_pid"
        case parentPid = "parent_pid"
    }
}

struct ExitPayload: Codable, Sendable {
    let pid: pid_t
    let exitCode: Int

    enum CodingKeys: String, CodingKey {
        case pid
        case exitCode = "exit_code"
    }
}

struct OpenPayload: Codable, Sendable {
    let pid: pid_t
    let path: String
    let flags: Int

    enum CodingKeys: String, CodingKey {
        case pid, path, flags
    }
}

/// ApplicationControlUndecidedPayload is the wire shape of the event the extension emits when AUTH_EXEC could not compute a
/// BINARY hash within the kernel deadline budget (or the file was unreadable for the TOCTOU re-stat reasons enumerated in
/// FileHashCache.computeSHA256WithDeadline) and the active snapshot's deadlineFallback drove the verdict. Operators consume
/// these events to size their cold-cache rate before flipping the posture between failClosed / failOpen / auditOnly:
///   - verdict carries the wire verdict ("allow" or "deny"). Operator dashboards group by this so the deny rate under
///     failClosed is distinguishable from the allow rate under auditOnly.
///   - reason carries the technical cause ("deadline" or "read_failed"). The two cases respond to different operator levers
///     (raise the safety margin vs investigate why the file is unreadable).
///   - fileSizeBytes is the size of the executable being authorised. Pairs with reason="deadline" to identify "we lose on
///     binaries larger than N MB" workloads where a future macOS deadline change or a hash-precompute side channel could
///     close the gap.
struct ApplicationControlUndecidedPayload: Codable, Sendable {
    let pid: pid_t
    let path: String
    let verdict: String
    let reason: String
    let fileSizeBytes: UInt64
    let policyID: Int64
    let policyVersion: Int64

    enum CodingKeys: String, CodingKey {
        case pid, path, verdict, reason
        case fileSizeBytes = "file_size_bytes"
        case policyID = "policy_id"
        case policyVersion = "policy_version"
    }
}

/// ApplicationControlBlockPayload is the wire shape of the event the
/// extension emits when AUTH_EXEC denies an exec. The server's
/// `application_control_block` catalog rule decodes this payload and
/// maps it to an alert with `source='application_control'`. Field
/// names match the Go decode struct in
/// `server/rules/internal/catalog/application_control_block.go`.
struct ApplicationControlBlockPayload: Codable, Sendable {
    let pid: pid_t
    let path: String
    let ruleID: String
    let ruleType: String
    let identifier: String
    let severity: String
    let customMsg: String?
    let customURL: String?
    let policyID: Int64
    let policyVersion: Int64

    enum CodingKeys: String, CodingKey {
        case pid, path
        case ruleID = "rule_id"
        case ruleType = "rule_type"
        case identifier
        case severity
        case customMsg = "custom_msg"
        case customURL = "custom_url"
        case policyID = "policy_id"
        case policyVersion = "policy_version"
    }
}

struct BtmLaunchItemAddPayload: Codable, Sendable {
    let itemType: String
    let itemPath: String
    let executablePath: String
    let legacy: Bool
    let managed: Bool
    let uid: uid_t
    // executableCodeSigning is the server rule's decision input (ADR-0008 amendment): the code-signing of the registered
    // executable, evaluated out-of-band via SecStaticCode. nil when executable_path is empty or unreadable.
    let executableCodeSigning: CodeSigning?
    let instigatorPid: pid_t
    let instigatorCodeSigning: CodeSigning?

    enum CodingKeys: String, CodingKey {
        case itemType = "item_type"
        case itemPath = "item_path"
        case executablePath = "executable_path"
        case legacy
        case managed
        case uid
        case executableCodeSigning = "executable_code_signing"
        case instigatorPid = "instigator_pid"
        case instigatorCodeSigning = "instigator_code_signing"
    }
}

// MARK: - Event envelope

struct EventEnvelope<P: Codable & Sendable>: Codable, Sendable {
    let eventID: String
    let hostID: String
    let timestampNs: UInt64
    let eventType: String
    let payload: P

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case hostID = "host_id"
        case timestampNs = "timestamp_ns"
        case eventType = "event_type"
        case payload
    }
}

// MARK: - Serializer

/// Serializes ESF event payloads into the canonical JSON event envelope.
final class EventSerializer: Sendable {
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = .sortedKeys
        return e
    }()

    private let hostID: String

    init() {
        self.hostID = Self.getHardwareUUID() ?? "unknown"
    }

    func serialize<P: Codable & Sendable>(eventType: String, payload: P) -> Data? {
        let envelope = EventEnvelope(
            eventID: UUID().uuidString,
            hostID: hostID,
            timestampNs: UInt64(clock_gettime_nsec_np(CLOCK_REALTIME)),
            eventType: eventType,
            payload: payload
        )

        do {
            return try encoder.encode(envelope)
        } catch {
            logger.error("Failed to encode \(eventType) event: \(error.localizedDescription)")
            return nil
        }
    }

    private static func getHardwareUUID() -> String? {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        guard platformExpert != 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }

        let uuidCF = IORegistryEntryCreateCFProperty(
            platformExpert,
            kIOPlatformUUIDKey as CFString,
            kCFAllocatorDefault,
            0
        )
        return uuidCF?.takeRetainedValue() as? String
    }
}
