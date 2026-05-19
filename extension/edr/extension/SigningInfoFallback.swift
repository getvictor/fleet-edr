import Foundation
import Security
import os

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "SigningInfoFallback")

/// SigningInfoFallback fills in the canonical Team ID for a binary when ESF returns an empty `target.team_id`.
///
/// Why this exists: on SIP-disabled environments, the kernel can flag developer-signed binaries as
/// `CS_PLATFORM_BINARY` (codesigning_flags bit 0x04000000). ESF surfaces `is_platform_binary=true` for those
/// processes and OMITS the team_id (platform binaries are Apple's; team_id is unset by convention).
/// AUTH_EXEC's TEAMID rule branch then has nothing to match against -- it cannot block a binary by
/// `8VBZ3948LU` if ESF says team_id="". On SIP-on production environments the kernel does not elevate
/// dev-signed binaries this way and ESF reports the real team_id; this fallback is a no-op there.
///
/// The fallback reads the binary on disk via SecStaticCode + SecCodeCopySigningInformation and returns the
/// `TeamIdentifier` value the codesign block declares. That is the same value `codesign -dvv` prints, and
/// matches the identifier the server-side TEAMID rule's operator would have typed.
///
/// Cost: SecCode walks the Mach-O signing block, which is a few hundred microseconds for a typical binary.
/// AUTH_EXEC's deadline (the kernel waits up to 60 seconds for our response by default) absorbs this; the
/// FileHashCache pattern of "kick async fill, return nil on cold cache" is unnecessary at this latency.
/// Results are cached in an inode+mtime-keyed dictionary so repeated execs of the same binary skip the
/// SecCode walk; the cache is purged on extension restart (cold path is rare and self-healing).
///
/// Concurrency: the cache is guarded by an OSAllocatedUnfairLock for the same reason
/// ApplicationControlStore's lock is -- AUTH_EXEC fires concurrently across CPUs and the critical section
/// is a constant-time dictionary lookup.
final class SigningInfoFallback {
    static let shared = SigningInfoFallback()

    /// CacheKey pins a cached signing-info entry to a specific (inode, mtime) tuple so a binary swap that
    /// preserves the path but changes the contents is observed as a cache miss. Stores mtime as separate
    /// sec / nsec fields to mirror FileHashCache.swift's CacheKey exactly: same invalidation contract,
    /// same shape, and no scalar multiplication that would trip SwiftLint's no_magic_numbers rule on the
    /// nanoseconds-per-second constant.
    struct CacheKey: Hashable {
        let inode: UInt64
        let mtimeSec: Int64
        let mtimeNsec: Int64
    }

    private let lock = OSAllocatedUnfairLock(initialState: [CacheKey: String?]())

    /// teamID returns the Team ID for the binary at `path`. Returns nil when:
    ///   - SecStaticCode cannot read the binary (permission denied, file gone)
    ///   - The signing dict does not contain a TeamIdentifier (ad-hoc signed binary)
    ///   - The signing info has a TeamIdentifier of empty string
    /// The first two are real "no Team ID" outcomes; the third should not happen in practice but is
    /// handled defensively. Caches the result keyed on (inode, mtime).
    func teamID(forPath path: String, fileStat: stat) -> String? {
        let key = CacheKey(
            inode: fileStat.st_ino,
            mtimeSec: Int64(fileStat.st_mtimespec.tv_sec),
            mtimeNsec: Int64(fileStat.st_mtimespec.tv_nsec),
        )
        if let cached = lock.withLock({ $0[key] }) {
            // Non-nil cached means we have read this file before; the value (which itself may be a real
            // String or nil) is the canonical answer. The outer optional pattern lets us distinguish
            // "never read" from "read, returned nil".
            return cached
        }
        let resolved = resolveTeamID(forPath: path)
        lock.withLock { $0[key] = resolved }
        return resolved
    }

    /// resolveTeamID is the uncached SecCode read. Split out so the cache path can stay terse.
    private func resolveTeamID(forPath path: String) -> String? {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            logger.debug("SecStaticCodeCreateWithPath failed for \(path, privacy: .private): \(createStatus)")
            return nil
        }
        var infoDict: CFDictionary?
        // kSecCSSigningInformation (rawValue=2) is the flag that asks SecCodeCopySigningInformation to populate the
        // signing-info keys -- including kSecCodeInfoTeamIdentifier. Without it the returned dict is missing the
        // TeamIdentifier entry entirely and the fallback silently returns nil (the bug that masked TEAMID enforcement
        // on SIP-off VMs end-to-end). The constant is the canonical Sec framework flag; using the literal rawValue
        // keeps the binding stable across SDK versions where the symbol's import name has drifted.
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoDict)
        guard infoStatus == errSecSuccess, let info = infoDict as? [String: Any] else {
            logger.debug("SecCodeCopySigningInformation failed for \(path, privacy: .private): \(infoStatus)")
            return nil
        }
        // The Sec framework spells this key "kSecCodeInfoTeamIdentifier" in its public header. Reference it
        // by the Foundation string constant so a future SDK rename surfaces at compile time rather than
        // silently returning nil.
        guard let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String, !teamID.isEmpty else {
            return nil
        }
        return teamID
    }
}
