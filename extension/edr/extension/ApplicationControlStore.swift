import Foundation
import os

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ApplicationControlStore")

// ApplicationControlSnapshot is the typed in-memory shape the AUTH_EXEC decision
// engine consults on every exec. Rules are indexed by (rule_type, identifier)
// so the precedence walk is O(1) per type. All five (CDHASH, BINARY, SIGNINGID,
// TEAMID, plus the deferred CERTIFICATE/PATH carriers) are populated.
//
// deadlineFallback governs the verdict the AUTH_EXEC handler applies when sync
// SHA-256 hashing for a BINARY rule consultation cannot complete within the
// kernel deadline budget. Per-snapshot because each policy carries its own
// posture on the wire (server/rules/api.SetApplicationControlPayload). Defaults
// to FallbackPosture.defaultPosture (failClosed) when the payload omits the
// field so older fan-out callers that haven't been recompiled against the new
// shape still produce a safe-by-default behaviour.
struct ApplicationControlSnapshot {
    let policyID: Int64
    let policyVersion: Int64
    let deadlineFallback: FallbackPosture
    let binaryRules: [String: ApplicationControlRule]      // identifier (file SHA-256) -> rule
    let cdhashRules: [String: ApplicationControlRule]      // 40 hex
    let signingIDRules: [String: ApplicationControlRule]   // "<TeamID>:<bundle.id>" or "platform:<bundle.id>"
    let certificateRules: [String: ApplicationControlRule] // 64 hex (leaf cert sha256)
    let teamIDRules: [String: ApplicationControlRule]      // 10 char TeamID
    let pathRules: [String: ApplicationControlRule]        // canonical absolute path

    static let empty = ApplicationControlSnapshot(
        policyID: 0,
        policyVersion: 0,
        deadlineFallback: .defaultPosture,
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
///
/// ruleID is the stable string identifier (e.g. "app_control:42") the
/// AUTH_EXEC handler echoes back in the `application_control_block` event
/// so the server's alert mapping lands the alert under the same rule_id.
struct ApplicationControlRule: Codable, Equatable {
    let ruleID: String
    let ruleType: String
    let identifier: String
    let action: String
    let enforcement: String
    let severity: String
    let customMsg: String?
    let customURL: String?

    enum CodingKeys: String, CodingKey {
        case ruleID = "rule_id"
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
///
/// deadlineFallback is Optional because the field was added in v0.1.0; older
/// agents and any captured pre-v0.1.0 payload on disk will not carry it. The
/// makeSnapshot helper substitutes FallbackPosture.defaultPosture when nil.
struct ApplicationControlDocument: Codable {
    let policyID: Int64
    let policyVersion: Int64
    let deadlineFallback: FallbackPosture?
    let rules: [ApplicationControlRule]

    enum CodingKeys: String, CodingKey {
        case policyID = "policy_id"
        case policyVersion = "policy_version"
        case deadlineFallback = "deadline_fallback"
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

/// Rule-action tokens that match the server enum exactly. The demo cut
/// only emits BLOCK; ALLOW and SILENT_BLOCK arrive with Phase B Lockdown.
enum ApplicationControlAction {
    static let block = "BLOCK"
    static let allow = "ALLOW"
    static let silentBlock = "SILENT_BLOCK"
}

/// Rule-enforcement tokens that match the server enum exactly. The demo
/// cut only enforces PROTECT (deny-on-match); DETECT (log only) arrives
/// with Phase B.
enum ApplicationControlEnforcement {
    static let protect = "PROTECT"
    static let detect = "DETECT"
}

/// ApplicationControlStore holds the typed in-memory snapshot consulted by
/// the AUTH_EXEC decision engine (Step 3). The snapshot also persists to
/// disk so the extension's policy survives restarts. Updates from the agent
/// come in via XPC and route through `apply(rawJSON:)`.
///
/// Concurrency:
///  - Reads of `currentSnapshot()` take the OSAllocatedUnfairLock for a
///    constant-time critical section. This is not literally lock-free; the
///    OS-level primitive is an inline-storage unfair lock optimised for
///    uncontended fast paths.
///  - Writes (apply, persist) happen on a serial dispatch queue.
///  - The disk write uses Data.write(to:options:.atomic), which writes a
///    temporary file and renames it atomically.
final class ApplicationControlStore {
    /// Singleton entry point used by every production callsite. The AUTH_EXEC handler, the XPC
    /// dispatcher and the extension's boot path all go through `.shared`. Tests should NOT use
    /// `.shared` because it persists to `/var/db/com.fleetdm.edr/application-control.json`, which
    /// is both global state and a real production file. Construct a per-test instance with
    /// `ApplicationControlStore(storagePath: tempFile)` instead so each test gets an empty
    /// snapshot AND the async persist lands in a temp directory the test cleans up.
    static let shared = ApplicationControlStore()

    private let lock = OSAllocatedUnfairLock(initialState: ApplicationControlSnapshot.empty)
    private let persistQueue = DispatchQueue(label: "com.fleetdm.edr.appcontrol.persist", qos: .utility)
    private let storagePath: String

    /// defaultStoragePath is the on-disk policy file the production singleton uses. Extracted from the init's default
    /// argument so Sonar S1075 (hardcoded URI in source) lands on the named constant rather than the function signature;
    /// the constant is still in one place and the doc-comment on `.shared` continues to discourage production callers
    /// from bypassing the singleton.
    static let defaultStoragePath = "/var/db/com.fleetdm.edr/application-control.json"

    /// The `storagePath` argument exists for XCTest isolation -- production code uses `.shared`
    /// which initializes via the default value (the real on-disk policy file under /var/db).
    /// The init is internal (not private) because @testable code in the SwiftPM Tests target
    /// needs to call it; the doc comment on `.shared` discourages new production callers from
    /// bypassing the singleton.
    init(storagePath: String = ApplicationControlStore.defaultStoragePath) {
        self.storagePath = storagePath
    }

    /// currentSnapshot returns the active snapshot. The AUTH_EXEC handler
    /// calls this on every exec, so the critical section is constant time
    /// (a copy of the small ApplicationControlSnapshot struct) and the
    /// underlying lock is an OSAllocatedUnfairLock tuned for uncontended
    /// fast paths.
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
        // Build the summary as a plain Swift String first, then interpolate it
        // as a single OSLogMessage placeholder. Going via String avoids the
        // SwiftLint line_length cap (the full interpolated form is >200 chars)
        // AND keeps the log statement a single Logger call, which is what
        // os.log's OSLogMessage type accepts (it has no `+` operator across
        // interpolation segments).
        let summary = "loaded app control snapshot: " +
            "policy=\(snapshot.policyID) version=\(snapshot.policyVersion) rules=\(document.rules.count)"
        logger.info("\(summary, privacy: .public)")
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
        // Same OSLogMessage / line_length pattern as in loadFromDisk above:
        // build the message as a plain String, then interpolate once.
        let summary = "applied app control snapshot: " +
            "policy=\(snapshot.policyID) version=\(snapshot.policyVersion) rules=\(document.rules.count)"
        logger.info("\(summary, privacy: .public)")
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
            deadlineFallback: document.deadlineFallback ?? .defaultPosture,
            binaryRules: binary,
            cdhashRules: cdhash,
            signingIDRules: signingID,
            certificateRules: certificate,
            teamIDRules: teamID,
            pathRules: path
        )
    }

    /// persist writes the raw payload to disk atomically. Data.write(to:options:.atomic)
    /// is implemented as write-temp-then-rename internally — Foundation manages
    /// the temp file and the rename in a single atomic swap that handles the
    /// destination-already-exists case correctly. No manual mv dance and no
    /// non-atomic window where the destination is missing.
    private func persist(rawJSON data: Data) {
        let url = URL(fileURLWithPath: storagePath)
        let directory = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: nil)
            try data.write(to: url, options: .atomic)
        } catch {
            logger.error("application control persist failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
