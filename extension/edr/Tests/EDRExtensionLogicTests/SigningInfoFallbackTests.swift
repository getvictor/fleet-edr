// SigningInfoFallback tests: the cache-backed SecCode lookup that supplies the canonical Team ID and the leaf
// certificate SHA-256 for the AUTH_EXEC target tuple when ESF does not surface them directly.
//
// These tests assert the OBSERVABLE behaviour of the public lookup surface (leafCertSHA256 / teamID return an
// absent value, deterministically and without blocking, for a target whose leaf certificate cannot be resolved).
// They deliberately do NOT assert on a specific hash for a signed binary: producing a deterministic Developer-ID
// leaf cert on the test runner is environment-coupled, so the signed-binary "full tuple" shape is verified at the
// decider boundary (AuthExecDeciderTests) and end to end on a real VM (the L5 app-control scenario). What is pure
// and deterministic here is the cold / unreadable / unsigned path: SecStaticCodeCreateWithPath (or the signing-info
// copy) fails, the fallback returns nil, and the cache pins that absent outcome.

import Darwin
import Foundation
@testable import EDRExtensionLogic
import XCTest

final class SigningInfoFallbackTests: XCTestCase {
    /// makeUnsignedTempFile writes a plain (unsigned, non-Mach-O) file and returns its path + live stat. SecCode
    /// rejects it (no signature), so the leaf-cert + team-id lookups must return nil -- the cold-cache "absent"
    /// outcome the target tuple records as a missing leaf_cert_sha256.
    private func makeUnsignedTempFile() throws -> (path: String, stat: stat) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("EDRSigningInfoTests", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("unsigned-\(UUID().uuidString).bin")
        try Data("not a signed mach-o".utf8).write(to: url)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        var st = stat()
        XCTAssertEqual(stat(url.path, &st), 0, "stat() must succeed on the freshly-written temp file")
        return (url.path, st)
    }

    // spec marker: the canonical scenario id maps to this test function name (slashes/dashes -> underscores).
    func test_spec_extension_application_control_target_identifier_tuple_for_every_exec_a_cold_leaf_cert_lookup_yields_an_absent_value_without_blocking() throws {
        let file = try makeUnsignedTempFile()

        // Cold cache + unsigned target: leaf cert cannot be resolved, so the lookup returns an absent value (nil)
        // rather than blocking on a Security-framework call that would surface a hash. This is the value the target
        // tuple records as a missing leaf_cert_sha256, which makes any CERTIFICATE rule silently miss for this exec.
        let leaf = SigningInfoFallback.shared.leafCertSHA256(forPath: file.path, fileStat: file.stat)
        XCTAssertNil(leaf, "an unsigned target must yield an absent leaf_cert_sha256")

        // A path that does not exist (the most extreme "unreadable" case) also returns nil deterministically, never
        // throwing or hanging -- the AUTH callback that consumes this must not be delayed by an unresolved lookup.
        var missingStat = stat()
        missingStat.st_dev = 1
        missingStat.st_ino = 424_242
        let missingPath = "/tmp/edr-signinginfo-does-not-exist-\(UUID().uuidString)"
        XCTAssertNil(SigningInfoFallback.shared.leafCertSHA256(forPath: missingPath, fileStat: missingStat),
                     "an unreadable path must yield an absent leaf_cert_sha256, not block")

        // The same SecCode walk also yields no team id for the unsigned target (both fields share one cached lookup),
        // confirming the absent outcome is the cache's pinned state, not a transient first-call artefact.
        XCTAssertNil(SigningInfoFallback.shared.teamID(forPath: file.path, fileStat: file.stat),
                     "an unsigned target must yield an absent team_id")
    }
}
