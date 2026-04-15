import Foundation
import IOKit
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "Serializer")

// MARK: - Payload types

struct NetworkConnectPayload: Codable, Sendable {
    let pid: pid_t
    let path: String
    let uid: uid_t
    let proto: String
    let direction: String
    let localAddress: String
    let localPort: UInt16
    let remoteAddress: String
    let remotePort: UInt16
    let remoteHostname: String

    enum CodingKeys: String, CodingKey {
        case pid, path, uid
        case proto = "protocol"
        case direction
        case localAddress = "local_address"
        case localPort = "local_port"
        case remoteAddress = "remote_address"
        case remotePort = "remote_port"
        case remoteHostname = "remote_hostname"
    }
}

struct DNSQueryPayload: Codable, Sendable {
    let pid: pid_t
    let path: String
    let uid: uid_t
    let queryName: String
    let queryType: String
    let responseAddresses: [String]?
    let proto: String

    enum CodingKeys: String, CodingKey {
        case pid, path, uid
        case queryName = "query_name"
        case queryType = "query_type"
        case responseAddresses = "response_addresses"
        case proto = "protocol"
    }
}

// MARK: - Event envelope (same as ESF extension)

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

final class NetworkEventSerializer: Sendable {
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = .sortedKeys
        return e
    }()

    private let hostID: String

    init() {
        if let uuid = Self.getHardwareUUID() {
            self.hostID = uuid
        } else {
            logger.warning("Hardware UUID not available, events will have empty host_id")
            self.hostID = ""
        }
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
