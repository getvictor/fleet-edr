import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ApplicationControlStore")

// ApplicationControlSnapshot is the typed in-memory shape the AUTH_EXEC decision
// engine (Step 3) consults on every exec. Rules are indexed by (rule_type,
// identifier) so the precedence walk is O(1) per type. Phase 1 of the demo cut
// only populates the BINARY map; the others are reserved for the follow-on
// types (CDHASH, SIGNINGID, CERTIFICATE, TEAMID, PATH) coming later.
struct ApplicationControlSnapshot {
    let policyID: Int64
    let policyVersion: Int64
    let binaryRules: [String: ApplicationControlRule]      // identifier (file SHA-256) -> rule
    let cdhashRules: [String: ApplicationControlRule]      // 40 hex
    let signingIDRules: [String: ApplicationControlRule]   // "<TeamID>:<bundle.id>" or "platform:<bundle.id>"
    let certificateRules: [String: ApplicationControlRule] // 64 hex (leaf cert sha256)
    let teamIDRules: [String: ApplicationControlRule]      // 10 char TeamID
    let pathRules: [String: ApplicationControlRule]        // canonical absolute path

    static let empty = ApplicationControlSnapshot(
        policyID: 0,
        policyVersion: 0,
        binaryRules: [:],
        cdhashRules: [:],
        signingIDRules: [:],
        certificateRules: [:],
        teamIDRules: [:],
        pathRules: [:]
    )
}

/// ApplicationControlRule mirrors one entry in the wire payload. Codable so
/// the same struct decodes both an incoming XPC payload and the persisted
/// snapshot file on disk. Field names use snake_case in JSON to match the
/// server's `server/rules/api.SetApplicationControlRule` JSON tags — a
/// rename on either side is a contract break and the round-trip test on the
/// server side is the gate.
struct ApplicationControlRule: Codable {
    let ruleType: String
    let identifier: String
    let action: String
    let enforcement: String
    let severity: String
    let customMsg: String?
    let customURL: String?

    enum CodingKeys: String, CodingKey {
        case ruleType = "rule_type"
        case identifier
        case action
        case enforcement
        case severity
        case customMsg = "custom_msg"
        case customURL = "custom_url"
    }
}

/// ApplicationControlDocument is the on-the-wire shape of the snapshot.
/// Identical to server/rules/api.SetApplicationControlPayload.
struct ApplicationControlDocument: Codable {
    let policyID: Int64
    let policyVersion: Int64
    let rules: [ApplicationControlRule]

    enum CodingKeys: String, CodingKey {
        case policyID = "policy_id"
        case policyVersion = "policy_version"
        case rules
    }
}

/// Rule-type tokens that match the server enum exactly. Stable across the
/// wire; renaming any constant is a contract break.
enum ApplicationControlRuleType {
    static let binary = "BINARY"
    static let cdhash = "CDHASH"
    static let signingID = "SIGNINGID"
    static let certificate = "CERTIFICATE"
    static let teamID = "TEAMID"
    static let path = "PATH"
}

/// ApplicationControlStore holds the typed in-memory snapshot consulted by
/// the AUTH_EXEC decision engine (Step 3). The snapshot also persists to
/// disk so the extension's policy survives restarts. Updates from the agent
/// come in via XPC and route through `apply(rawJSON:)`.
///
/// Concurrency:
///  - Reads of `currentSnapshot()` are lock-free via OSAllocatedUnfairLock.
///  - Writes (apply, persist) happen on a serial queue.
///  - The disk write uses write-temp-then-rename so a crash mid-write cannot
///    leave the file partially written.
final class ApplicationControlStore {
    static let shared = ApplicationControlStore()

    private let lock = OSAllocatedUnfairLock(initialState: ApplicationControlSnapshot.empty)
    private let persistQueue = DispatchQueue(label: "com.fleetdm.edr.appcontrol.persist", qos: .utility)
    private let storagePath = "/var/db/com.fleetdm.edr/application-control.json"

    /// currentSnapshot returns the active snapshot. Lock-free fast path: the
    /// AUTH_EXEC handler will call this on every exec, so it must be O(1)
    /// and never block.
    func currentSnapshot() -> ApplicationControlSnapshot {
        return lock.withLock { $0 }
    }

    /// loadFromDisk reads the persisted snapshot at startup. Missing file or
    /// decode error fails open (empty snapshot) — the agent will push the
    /// current snapshot on its next command poll cycle. Never fatal.
    func loadFromDisk() {
        let url = URL(fileURLWithPath: storagePath)
        guard let data = try? Data(contentsOf: url) else {
            logger.info("no persisted application control snapshot at startup")
            return
        }
        guard let document = decodeDocument(data) else {
            logger.warning("failed to decode persisted application control snapshot; starting empty")
            return
        }
        let snapshot = makeSnapshot(from: document)
        lock.withLock { $0 = snapshot }
        logger.info("loaded application control snapshot: policy=\(snapshot.policyID, privacy: .public) version=\(snapshot.policyVersion, privacy: .public) rules=\(document.rules.count, privacy: .public)")
    }

    /// apply decodes the raw JSON from an `application_control.update` XPC
    /// message, validates version monotonicity (the server bumps version on
    /// every mutation; an equal or smaller version is either a duplicate
    /// delivery or an out-of-order replay and must not regress the active
    /// snapshot), atomically swaps the in-memory state, and persists the
    /// new snapshot to disk.
    func apply(rawJSON data: Data) {
        guard let document = decodeDocument(data) else {
            logger.error("application_control.update missing or malformed; ignoring")
            return
        }
        let snapshot = makeSnapshot(from: document)

        var applied = false
        lock.withLock { current in
            // Monotonic-version gate. A duplicate delivery (same version) is
            // not an error — the agent retries on its next poll if the
            // previous cycle's ack failed — but we still skip the swap so
            // the disk write doesn't fire for a no-op.
            if snapshot.policyID == current.policyID && snapshot.policyVersion <= current.policyVersion {
                return
            }
            current = snapshot
            applied = true
        }
        if !applied {
            logger.info("application_control.update version \(snapshot.policyVersion, privacy: .public) <= current; ignoring")
            return
        }
        logger.info("applied application control snapshot: policy=\(snapshot.policyID, privacy: .public) version=\(snapshot.policyVersion, privacy: .public) rules=\(document.rules.count, privacy: .public)")
        persistQueue.async { [data] in
            self.persist(rawJSON: data)
        }
    }

    private func decodeDocument(_ data: Data) -> ApplicationControlDocument? {
        let decoder = JSONDecoder()
        return try? decoder.decode(ApplicationControlDocument.self, from: data)
    }

    private func makeSnapshot(from document: ApplicationControlDocument) -> ApplicationControlSnapshot {
        var binary: [String: ApplicationControlRule] = [:]
        var cdhash: [String: ApplicationControlRule] = [:]
        var signingID: [String: ApplicationControlRule] = [:]
        var certificate: [String: ApplicationControlRule] = [:]
        var teamID: [String: ApplicationControlRule] = [:]
        var path: [String: ApplicationControlRule] = [:]
        for rule in document.rules {
            switch rule.ruleType {
            case ApplicationControlRuleType.binary:
                binary[rule.identifier] = rule
            case ApplicationControlRuleType.cdhash:
                cdhash[rule.identifier] = rule
            case ApplicationControlRuleType.signingID:
                signingID[rule.identifier] = rule
            case ApplicationControlRuleType.certificate:
                certificate[rule.identifier] = rule
            case ApplicationControlRuleType.teamID:
                teamID[rule.identifier] = rule
            case ApplicationControlRuleType.path:
                path[rule.identifier] = rule
            default:
                // The server validator already gates rule_type, so an unknown
                // value here is a contract break the operator audit log will
                // surface upstream. Skip the entry rather than dropping the
                // whole snapshot.
                logger.warning("application_control.update unknown rule_type; skipping entry")
            }
        }
        return ApplicationControlSnapshot(
            policyID: document.policyID,
            policyVersion: document.policyVersion,
            binaryRules: binary,
            cdhashRules: cdhash,
            signingIDRules: signingID,
            certificateRules: certificate,
            teamIDRules: teamID,
            pathRules: path
        )
    }

    /// persist writes the raw payload to disk via write-temp-then-rename so a
    /// crash mid-write cannot leave the file partially written. Creates the
    /// parent directory if missing.
    private func persist(rawJSON data: Data) {
        let directory = (storagePath as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: nil)
        } catch {
            logger.error("application control persist mkdir failed: \(error.localizedDescription, privacy: .public)")
            return
        }
        let tmpPath = storagePath + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmpPath), options: .atomic)
        } catch {
            logger.error("application control persist write failed: \(error.localizedDescription, privacy: .public)")
            return
        }
        do {
            try FileManager.default.moveItem(atPath: tmpPath, toPath: storagePath)
        } catch {
            // moveItem fails if the destination exists. Remove and retry.
            do {
                try FileManager.default.removeItem(atPath: storagePath)
                try FileManager.default.moveItem(atPath: tmpPath, toPath: storagePath)
            } catch {
                logger.error("application control persist rename failed: \(error.localizedDescription, privacy: .public)")
                try? FileManager.default.removeItem(atPath: tmpPath)
                return
            }
        }
    }
}
