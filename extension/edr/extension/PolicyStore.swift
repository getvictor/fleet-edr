import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "PolicyStore")

/// On-disk JSON for the policy payload. Version is monotonically increasing; paths is the
/// set of absolute file paths ESF should DENY under AUTH_EXEC. Hashes is reserved for a
/// future SHA-256 block list — recognised on the wire, ignored at runtime today.
struct PolicyDocument: Codable {
    let name: String
    let version: Int64
    let paths: [String]
    let hashes: [String]
}

/// PolicyStore owns the runtime blocklist. Writes happen on a serial queue so concurrent
/// XPC deliveries can't interleave; reads from ESF's AUTH_EXEC handler are atomic pointer
/// loads so the hot path doesn't block on the writer.
///
/// Persistence is atomic file replacement (write sibling .tmp → rename). A crash mid-write
/// leaves either the previous good version or nothing — never a half-written file.
final class PolicyStore {
    static let shared = PolicyStore()

    /// Absolute path where the policy JSON is persisted. The directory is created on first
    /// write; mode is 0700 (owner rwx) because this file contains paths the operator wants
    /// kept confidential.
    private static let storagePath = "/var/db/com.fleetdm.edr/policy.json"

    private let queue = DispatchQueue(label: "com.fleetdm.edr.policystore")

    // `nonisolated(unsafe)` is used here because the Swift compiler can't prove the
    // exclusive-access invariant — we guarantee it manually: mutations go through `queue`,
    // reads on the ESF hot path are atomic Set assignments.
    nonisolated(unsafe) private var currentPathsValue: Set<String> = []
    nonisolated(unsafe) private var currentVersion: Int64 = 0

    private init() {}

    /// loadFromDisk populates the in-memory state from the persisted file. Called from
    /// main.swift at extension start. Missing file or malformed JSON both result in an
    /// empty blocklist — safer to fail-open on startup than to reject all execs.
    func loadFromDisk() {
        queue.sync {
            let url = URL(fileURLWithPath: Self.storagePath)
            guard let data = try? Data(contentsOf: url) else {
                logger.info("no persisted policy at \(Self.storagePath, privacy: .public); starting empty")
                return
            }
            do {
                let doc = try JSONDecoder().decode(PolicyDocument.self, from: data)
                self.currentPathsValue = Set(doc.paths)
                self.currentVersion = doc.version
                logger.info("policy loaded from disk: version=\(doc.version), paths=\(doc.paths.count)")
            } catch {
                // Corrupt or schema-incompatible file: start empty and log. A future PUT
                // will overwrite the file with a good version.
                logger.error("failed to decode persisted policy: \(error.localizedDescription, privacy: .public); starting empty")
            }
        }
    }

    /// apply ingests a raw JSON payload (the bytes the agent forwards over XPC) and
    /// atomically swaps the in-memory set + persists the new version. Called from
    /// XPCServer's peer dispatch.
    func apply(rawJSON: Data) {
        queue.sync {
            let doc: PolicyDocument
            do {
                doc = try JSONDecoder().decode(PolicyDocument.self, from: rawJSON)
            } catch {
                logger.error("policy decode failed: \(error.localizedDescription, privacy: .public)")
                return
            }
            // Accept lower or equal versions as a deliberate "re-apply" signal — Phase 2
            // server may re-send the same version on reconnect. The blocklist content is
            // what we actually use; `version` is a cheap audit marker.
            self.currentPathsValue = Set(doc.paths)
            self.currentVersion = doc.version
            self.persist(rawJSON: rawJSON)
            logger.info("policy applied: version=\(doc.version), paths=\(doc.paths.count)")
        }
    }

    /// currentBlockedPaths is the AUTH_EXEC hot-path read. It returns the Set as-of-now;
    /// the caller treats the result as immutable (it is — `Set` in Swift is value-typed).
    func currentBlockedPaths() -> Set<String> {
        // `queue.sync` on a serial queue is a read barrier; the alternative (a lock-free
        // atomic pointer swap) is more code for negligible hot-path gain on ESF's scale.
        queue.sync { self.currentPathsValue }
    }

    /// currentVersionSnapshot is exposed so future log lines / /metrics endpoints can
    /// report the applied version alongside the host.
    func currentVersionSnapshot() -> Int64 {
        queue.sync { self.currentVersion }
    }

    // MARK: - Persistence

    private func persist(rawJSON: Data) {
        let fm = FileManager.default
        let url = URL(fileURLWithPath: Self.storagePath)
        let parent = url.deletingLastPathComponent()

        // Ensure the directory exists; 0700 so only root can read the policy file.
        if !fm.fileExists(atPath: parent.path) {
            do {
                try fm.createDirectory(
                    at: parent, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: NSNumber(value: 0o700)]
                )
            } catch {
                logger.error("create policy dir failed: \(error.localizedDescription, privacy: .public)")
                return
            }
        }

        // Write to a sibling tmp file, then rename. This is the stdlib-atomic replace; a
        // crash between write and rename leaves the previous good file untouched.
        let tmp = parent.appendingPathComponent("policy.json.tmp")
        do {
            try rawJSON.write(to: tmp, options: .atomic)
            try fm.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: tmp.path)
            if fm.fileExists(atPath: url.path) {
                // FileManager.replaceItem handles the cross-device-rename edge case and
                // preserves the tmp file's perms on the replacement.
                _ = try fm.replaceItemAt(url, withItemAt: tmp)
            } else {
                try fm.moveItem(at: tmp, to: url)
            }
        } catch {
            logger.error("persist policy failed: \(error.localizedDescription, privacy: .public)")
            // Clean up the tmp file on failure so we don't accumulate broken leftovers.
            try? fm.removeItem(at: tmp)
        }
    }
}
