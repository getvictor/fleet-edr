import CryptoKit
import Foundation
import Security
import os

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "SigningInfoFallback")

/// SigningInfoFallback fills in the canonical Team ID and the leaf certificate SHA-256 for a binary when ESF does not provide
/// them directly. Both fields come from one SecCodeCopySigningInformation call so the cache pays the SecCode cost once per
/// (inode, mtime) regardless of which field a caller asks for first.
///
/// TeamID context: ESF redacts `target.team_id=""` and forces `target.is_platform_binary=true` for every exec the client sees
/// when the ESF host extension itself is not Developer-ID-signed + notarized. This is a documented per-client policy, not a
/// per-binary CS_PLATFORM_BINARY classification: the redaction hits every exec, including unambiguously third-party Developer-ID
/// signed binaries (issue #187 quantified 393/393 exec events redacted on edr-dev). The edr-dev VM ships the extension ad-hoc-
/// signed (`codesign -d` reports `adhoc, linker-signed`), which trips the redaction; AUTH_EXEC's TEAMID rule branch then has
/// nothing to match against -- it cannot block a binary by `8VBZ3948LU` if ESF says team_id="". On notarized release hosts ESF
/// reports the real team_id and this fallback is a no-op for the TEAM ID path. The proper long-term fix is to notarize the
/// extension (tracked separately); this fallback keeps the dev VM usable for end-to-end QA of TEAMID + SIGNINGID rule flows
/// in the meantime.
///
/// CERTIFICATE context (PR for #210): ESF does NOT surface the leaf X.509 signing certificate hash at all. SecCode is the only
/// path the extension has to derive it. Operators set CERTIFICATE rules with the SHA-256 of the leaf cert -- the value Santa
/// admins type, and the same hash `openssl x509 -fingerprint -sha256` would compute over the DER-encoded leaf. Every AUTH_EXEC
/// on a signed binary pays one SecCode walk on first exec, then cache hits.
///
/// The fallback reads the binary on disk via SecStaticCode + SecCodeCopySigningInformation. The TeamIdentifier value the
/// codesign block declares matches what `codesign -dvv` prints; the leaf cert SHA-256 matches what
/// `codesign -d --extract-certificates` + `shasum -a 256` would produce against the index-0 (leaf) cert.
///
/// Cost: SecCode walks the Mach-O signing block, which is a few hundred microseconds for a typical binary. AUTH_EXEC's
/// deadline (the kernel waits up to 60 seconds for our response by default) absorbs this; the FileHashCache pattern of "kick
/// async fill, return nil on cold cache" is unnecessary at this latency. Results cache in an inode+mtime-keyed dictionary so
/// repeated execs of the same binary skip the SecCode walk; the cache is purged on extension restart (cold path is rare and
/// self-healing).
///
/// Concurrency: the cache is guarded by an OSAllocatedUnfairLock for the same reason ApplicationControlStore's lock is --
/// AUTH_EXEC fires concurrently across CPUs and the critical section is a constant-time dictionary lookup.
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

    /// SigningInfo carries every field one SecCodeCopySigningInformation call extracts. Nil fields indicate "the key was
    /// absent or empty in the codesign info dict" (e.g. ad-hoc-signed binaries have no TeamIdentifier; unsigned binaries have
    /// no certificate chain). Equatable so the test suite can assert on the cache state directly.
    struct SigningInfo: Equatable {
        let teamID: String?
        let leafCertSHA256: String?
    }

    private let lock = OSAllocatedUnfairLock(initialState: [CacheKey: SigningInfo]())

    /// teamID returns the Team ID for the binary at `path`. Convenience wrapper for callers that only want the team-id
    /// branch; first call populates the shared SigningInfo cache, subsequent calls hit it.
    func teamID(forPath path: String, fileStat: stat) -> String? {
        return signingInfo(forPath: path, fileStat: fileStat).teamID
    }

    /// leafCertSHA256 returns the 64-character lowercase hex SHA-256 of the binary's leaf signing certificate. The "leaf"
    /// is the cert at index 0 of kSecCodeInfoCertificates -- the cert the binary was directly signed with, NOT an
    /// intermediate or the root. Returns nil for unsigned binaries, ad-hoc-signed binaries, or any path SecCode rejects.
    /// CERTIFICATE rules created against the operator-provided 64-hex identifier compare against this value verbatim.
    func leafCertSHA256(forPath path: String, fileStat: stat) -> String? {
        return signingInfo(forPath: path, fileStat: fileStat).leafCertSHA256
    }

    /// signingInfo is the cached SecCode-backed lookup. Both teamID(forPath:fileStat:) and leafCertSHA256(forPath:fileStat:)
    /// route through here so a binary that needs both lookups (the common case on AUTH_EXEC when both TEAMID and CERTIFICATE
    /// rule maps are non-empty) pays the SecCode cost exactly once.
    private func signingInfo(forPath path: String, fileStat: stat) -> SigningInfo {
        let key = CacheKey(
            inode: fileStat.st_ino,
            mtimeSec: Int64(fileStat.st_mtimespec.tv_sec),
            mtimeNsec: Int64(fileStat.st_mtimespec.tv_nsec),
        )
        if let cached = lock.withLock({ $0[key] }) {
            return cached
        }
        let resolved = resolveSigningInfo(forPath: path)
        lock.withLock { $0[key] = resolved }
        return resolved
    }

    /// resolveSigningInfo is the uncached SecCode read. One SecStaticCodeCreateWithPath + one SecCodeCopySigningInformation
    /// produces both the TeamIdentifier and the leaf certificate, even though the call sites may consume them at different
    /// times. Errors from either step return an empty SigningInfo (both fields nil) so the cache write still pins the
    /// outcome -- otherwise every AUTH_EXEC for an unreadable / unsigned binary would re-walk SecCode pointlessly.
    private func resolveSigningInfo(forPath path: String) -> SigningInfo {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            logger.debug("SecStaticCodeCreateWithPath failed for \(path, privacy: .private): \(createStatus)")
            return SigningInfo(teamID: nil, leafCertSHA256: nil)
        }
        var infoDict: CFDictionary?
        // kSecCSSigningInformation (rawValue=2) is the flag that asks SecCodeCopySigningInformation to populate the signing-info
        // keys -- including kSecCodeInfoTeamIdentifier AND kSecCodeInfoCertificates. Without it the returned dict is missing both
        // entries and this method silently returns the all-nil shape (the bug that masked TEAMID enforcement on SIP-off VMs end-
        // to-end before the explicit flag was added). The constant is the canonical Sec framework flag; using the literal
        // rawValue keeps the binding stable across SDK versions where the symbol's import name has drifted.
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoDict)
        guard infoStatus == errSecSuccess, let info = infoDict as? [String: Any] else {
            logger.debug("SecCodeCopySigningInformation failed for \(path, privacy: .private): \(infoStatus)")
            return SigningInfo(teamID: nil, leafCertSHA256: nil)
        }
        let team = extractTeamID(from: info)
        let leaf = extractLeafCertSHA256(from: info)
        return SigningInfo(teamID: team, leafCertSHA256: leaf)
    }

    /// extractTeamID pulls the TeamIdentifier value out of the codesign info dict, returning nil when the key is absent or
    /// the value is the empty string. Ad-hoc-signed binaries land in the nil case; Developer-ID-signed binaries return the
    /// 10-char team id verbatim.
    private func extractTeamID(from info: [String: Any]) -> String? {
        // The Sec framework spells this key "kSecCodeInfoTeamIdentifier" in its public header. Reference it by the Foundation
        // string constant so a future SDK rename surfaces at compile time rather than silently returning nil.
        guard let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String, !teamID.isEmpty else {
            return nil
        }
        return teamID
    }

    /// extractLeafCertSHA256 SHA-256s the DER bytes of the binary's leaf certificate (kSecCodeInfoCertificates[0]) and returns
    /// the 64-char lowercase hex digest. Returns nil for unsigned / ad-hoc-signed binaries (no certificate chain) or when the
    /// chain decode produces zero certs (defensive; never happens in practice for a signed binary). Gemini flagged the
    /// SecCertificateCopyData forced cast on PR #290; the conditional bind below treats a nil return defensively even though
    /// SecCertificateCopyData is documented as non-failing for a valid SecCertificate.
    private func extractLeafCertSHA256(from info: [String: Any]) -> String? {
        guard let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf = certs.first,
              let der = SecCertificateCopyData(leaf) as Data? else {
            return nil
        }
        let digest = SHA256.hash(data: der)
        return digestToHex(digest)
    }

    /// digestToHex renders a SHA-256 digest as 64 lowercase hex characters. Uses the explicit nibble-lookup pattern instead
    /// of String(format: "%02x", _) so the hex render is allocation-conscious and SwiftLint's no_magic_numbers rule has no
    /// literal `2` to flag. Mirrors the cdhashHexString shape in CDHashHex.swift; if a third hex consumer lands, lift this
    /// + cdhashHexString into a shared helper file.
    private func digestToHex(_ digest: SHA256.Digest) -> String {
        var s = ""
        s.reserveCapacity(SHA256.byteCount * digestHexCharsPerByte)
        for byte in digest {
            s.append(digestHexDigits[Int(byte >> digestHexShift)])
            s.append(digestHexDigits[Int(byte & digestLowNibbleMask)])
        }
        return s
    }
}

/// digestHexCharsPerByte is the fixed 2-char expansion ratio per byte. Named so SwiftLint's no_magic_numbers rule has nothing
/// to flag in digestToHex above.
private let digestHexCharsPerByte = 2

/// digestHexShift is the bit shift used to extract the high nibble of a byte. 4 bits per nibble; named to satisfy the lint.
private let digestHexShift: UInt8 = 4

/// digestLowNibbleMask is the bitmask used to extract the low nibble of a byte.
private let digestLowNibbleMask: UInt8 = 0x0f

/// digestHexDigits is the lookup table the digest-to-hex helper walks instead of calling String(format: "%02x", b). Mirrors
/// the hexDigitsLowercase in ESFSubscriber.swift.
private let digestHexDigits: [Character] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"
]
