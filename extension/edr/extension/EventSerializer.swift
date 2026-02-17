import Foundation
import IOKit
import os.log

private let logger = Logger(subsystem: "com.fleet.edr.extension", category: "EventSerializer")

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

    enum CodingKeys: String, CodingKey {
        case pid, ppid, path, args, cwd, uid, gid
        case codeSigning = "code_signing"
        case sha256
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
