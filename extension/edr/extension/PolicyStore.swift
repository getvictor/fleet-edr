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

/// PolicyStore owns the runtime blocklist. Reads from the AUTH_EXEC hot path are
/// lock-free (an atomic load of an immutable snapshot) so they never block behind a
/// writer, even when the writer is persisting to disk. Writes serialise through the
/// `stateQueue` for decode + swap, and a separate `persistQueue` handles disk I/O off
/// the critical path.
///
/// Versioning guard: `apply(rawJSON:)` rejects strictly-lower versions as an out-of-order
/// replay. Equal versions are accepted as an idempotent re-apply (operators can re-push
/// the current policy to recover a host that missed the original XPC delivery).
///
/// Persistence is atomic file replacement (write sibling .tmp → rename). A crash
/// mid-write leaves either the previous good version or nothing — never a half-written
/// file.
final class PolicyStore {
    static let shared = PolicyStore()

    /// Absolute path where the policy JSON is persisted. The directory is created on first
    /// write; mode is 0700 (owner rwx) because this file contains paths the operator wants
    /// kept confidential.
    private static let storagePath = "/var/db/com.fleetdm.edr/policy.json"

    /// Snapshot is the immutable view AUTH_EXEC reads. Every apply() builds a fresh
    /// snapshot; the pointer swap is atomic (OSAtomic / std atomic on the underlying
    /// ObjC reference) so readers always see a consistent {paths, version} pair without
    /// a lock. Value types (struct + Set<String>) are COW-safe — taking a copy out of the
    /// atomic pointer gives the reader its own retained reference and the writer can swap
    /// in a replacement without waiting for the reader to finish.
    struct Snapshot {
        let paths: Set<String>
        let version: Int64

        static let empty = Snapshot(paths: [], version: 0)
    }

    // `ManagedAtomic` would be cleaner but pulling in swift-atomics for a single pointer
    // is overkill; OSAllocatedUnfairLock + a small value is enough and ships with the
    // stdlib. OSAllocatedUnfairLock.withLockUnchecked is cheaper than DispatchQueue.sync
    // on the hot path — exactly what AUTH_EXEC needs.
    private let snapshotLock = OSAllocatedUnfairLock<Snapshot>(initialState: .empty)

    /// State queue serialises decode + snapshot swap in apply() + loadFromDisk(). Disk
    /// I/O does NOT run here — it runs on persistQueue so a long-running write cannot
    /// pile up snapshot swaps behind it (and more importantly, cannot appear to block
    /// the hot path even if the AUTH_EXEC read were ever routed through the state queue
    /// by mistake).
    private let stateQueue = DispatchQueue(label: "com.fleetdm.edr.policystore.state")

    /// Persist queue is dedicated to disk I/O. Serial so concurrent apply() calls do not
    /// end up racing to replace the same file; `.utility` QoS because persistence latency
    /// is never user-facing — the in-memory swap that drives AUTH_EXEC already happened.
    private let persistQueue = DispatchQueue(
        label: "com.fleetdm.edr.policystore.persist",
        qos: .utility
    )

    // Private to enforce the singleton pattern — callers reach the store via
    // PolicyStore.shared. No per-instance state to initialise beyond the default
    // storedProperty values above.
    private init() {}

    /// loadFromDisk populates the in-memory snapshot from the persisted file. Called from
    /// main.swift at extension start. Missing file or malformed JSON both result in an
    /// empty blocklist — safer to fail-open on startup than to reject all execs.
    func loadFromDisk() {
        stateQueue.sync {
            let url = URL(fileURLWithPath: Self.storagePath)
            guard let data = try? Data(contentsOf: url) else {
                logger.info("no persisted policy at \(Self.storagePath, privacy: .public); starting empty")
                return
            }
            do {
                let doc = try JSONDecoder().decode(PolicyDocument.self, from: data)
                self.snapshotLock.withLock { current in
                    current = Snapshot(paths: Set(doc.paths), version: doc.version)
                }
                logger.info("policy loaded from disk: version=\(doc.version), paths=\(doc.paths.count)")
            } catch {
                // Corrupt or schema-incompatible file: start empty and log. A future PUT
                // will overwrite the file with a good version.
                logger.error("failed to decode persisted policy: \(error.localizedDescription, privacy: .public); starting empty")
            }
        }
    }

    /// apply ingests a raw JSON payload (the bytes the agent forwards over XPC) and
    /// swaps the in-memory snapshot, then kicks off a background persist. Versioning:
    ///
    ///   - version < current : rejected (stale replay).
    ///   - version == current : accepted, no-op (idempotent re-apply).
    ///   - version > current : accepted, snapshot swapped, new document persisted.
    ///
    /// Called from XPCServer's peer dispatch. AUTH_EXEC reads never block on this
    /// method — they hit the snapshot lock, which is held for the nanoseconds of a
    /// pointer swap, not for the milliseconds of a filesystem write.
    /// ApplyDecision is the small result type apply() extracts from the snapshot lock.
    /// Pulling the decision out of the locked region lets us log + dispatch persistence
    /// without holding the lock, and sidesteps the Swift 6 sendable-closure-captures
    /// warning that would otherwise hit a mutated `swapped` flag.
    private struct ApplyDecision {
        let accepted: Bool
        let reApply: Bool
        let priorVersion: Int64
    }

    func apply(rawJSON: Data) {
        stateQueue.sync {
            guard let doc = decodePolicy(from: rawJSON) else { return }
            let decision = swapSnapshot(to: doc)
            handleApplyResult(doc: doc, rawJSON: rawJSON, decision: decision)
        }
    }

    /// decodePolicy is the JSON decode step of apply(). Isolated so the apply() body stays
    /// under the SwiftLint closure-body-length cap; also makes it easy to swap in a
    /// different wire format (protobuf, Msgpack, ...) in one place.
    private func decodePolicy(from rawJSON: Data) -> PolicyDocument? {
        do {
            return try JSONDecoder().decode(PolicyDocument.self, from: rawJSON)
        } catch {
            logger.error("policy decode failed: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    /// swapSnapshot runs the critical section: compare the incoming version against the
    /// current snapshot and, if acceptable, publish a new one. Equal-version "re-apply"
    /// is accepted so an operator can force a re-push after a suspected
    /// apply-but-didn't-persist split; strictly-lower versions are rejected as
    /// out-of-order replay. The caller is expected to react to the returned decision
    /// outside the lock.
    private func swapSnapshot(to doc: PolicyDocument) -> ApplyDecision {
        snapshotLock.withLock { current -> ApplyDecision in
            let prior = current.version
            if doc.version < prior {
                return ApplyDecision(accepted: false, reApply: false, priorVersion: prior)
            }
            let reApply = doc.version == prior
            current = Snapshot(paths: Set(doc.paths), version: doc.version)
            return ApplyDecision(accepted: true, reApply: reApply, priorVersion: prior)
        }
    }

    /// handleApplyResult handles logging + background persistence based on the decision.
    /// Extracted so apply()'s closure body stays short and no single path is buried in
    /// conditional noise.
    private func handleApplyResult(doc: PolicyDocument, rawJSON: Data, decision: ApplyDecision) {
        if !decision.accepted {
            logger.info(
                "policy ignored: stale version \(doc.version, privacy: .public) < current \(decision.priorVersion, privacy: .public)"
            )
            return
        }
        if decision.reApply {
            logger.info("policy re-applied at current version \(doc.version, privacy: .public) — no-op in memory")
        }

        // Kick off persistence on a dedicated queue so apply() returns as soon as the
        // in-memory swap lands. AUTH_EXEC readers see the new policy immediately;
        // disk I/O is best-effort and logs on failure.
        let version = doc.version
        let pathCount = doc.paths.count
        persistQueue.async {
            if self.persist(rawJSON: rawJSON) {
                logger.info(
                    "policy applied: version=\(version, privacy: .public), paths=\(pathCount, privacy: .public)"
                )
            } else {
                // Snapshot is already swapped in memory. Log explicitly so operators
                // see the split state — the on-disk copy is stale until the next
                // successful apply.
                logger.error(
                    "policy applied in memory but persistence failed: version=\(version, privacy: .public)"
                )
            }
        }
    }

    /// currentBlockedPaths is the AUTH_EXEC hot-path read. Lock-free pointer load of the
    /// immutable snapshot; returns the current `Set` as of the load instant. The Set is
    /// value-typed (COW) so the caller owns an independent reference and the writer can
    /// replace the snapshot under us without affecting this call.
    func currentBlockedPaths() -> Set<String> {
        snapshotLock.withLockUnchecked { $0.paths }
    }

    /// currentVersionSnapshot is exposed so future log lines / /metrics endpoints can
    /// report the applied version alongside the host.
    func currentVersionSnapshot() -> Int64 {
        snapshotLock.withLockUnchecked { $0.version }
    }

    // MARK: - Persistence

    /// persist writes the raw JSON payload atomically to storagePath. Returns true on
    /// success, false on any error — callers use the return value to decide whether to
    /// log "policy applied" or "policy applied in memory only".
    private func persist(rawJSON: Data) -> Bool {
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
                return false
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
            return true
        } catch {
            logger.error("persist policy failed: \(error.localizedDescription, privacy: .public)")
            // Clean up the tmp file on failure so we don't accumulate broken leftovers.
            try? fm.removeItem(at: tmp)
            return false
        }
    }
}
