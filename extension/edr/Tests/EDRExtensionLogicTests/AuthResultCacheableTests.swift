// AuthResultCacheableTests pins authResultIsCacheable: the pure mapping from an AuthDecision (plus the lazily-resolved
// identity state) to the kernel-cache flag the AUTH_EXEC wire side passes to es_respond_auth_result (#209). The wire call
// lives in ESFSubscriber.swift (excluded from this target because it imports EndpointSecurity), so this is the only layer
// that can pin the contract below the system / VM run. A FULLY RESOLVED decided ALLOW is cacheable; a cold-miss ALLOW (the
// BINARY hash timed out / could not be read, or a CERTIFICATE rule silently missed a not-yet-cached leaf cert) and every
// DENY are not, so the kernel does not short-circuit the re-exec that would warm the cache and let the block rule fire.

@testable import EDRExtensionLogic
import XCTest

final class AuthResultCacheableTests: XCTestCase {
    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/a-decided-allow-is-cached-at-the-kernel
    func testFullyResolvedAllowIsCacheable() {
        // Hash computed + no certificate rules: identity fully resolved, nothing left to warm.
        XCTAssertTrue(authResultIsCacheable(
            .allow, hashOutcome: .computed("abc"), leafCertResolved: false, snapshotHasCertificateRules: false))
        // No BINARY rules (hash not needed) + certificate rules present but the leaf cert was resolved.
        XCTAssertTrue(authResultIsCacheable(
            .allow, hashOutcome: .notNeeded, leafCertResolved: true, snapshotHasCertificateRules: true))
    }

    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/a-cold-miss-allow-is-not-cached
    func testColdMissAllowIsNotCacheable() {
        // BINARY hash unresolved (deadline / read failure under a fail-open posture): a warm re-hash could match a BINARY
        // block rule, so do not let the kernel cache short-circuit it.
        XCTAssertFalse(authResultIsCacheable(
            .allow, hashOutcome: .deadlineExceeded, leafCertResolved: true, snapshotHasCertificateRules: false),
            "a deadline-exceeded allow must not be cached")
        XCTAssertFalse(authResultIsCacheable(
            .allow, hashOutcome: .readFailed, leafCertResolved: true, snapshotHasCertificateRules: false),
            "a read-failure allow must not be cached")
        // Certificate rules present but the leaf cert was cold (silent miss): a warm cert could match a CERTIFICATE block
        // rule, so do not cache.
        XCTAssertFalse(authResultIsCacheable(
            .allow, hashOutcome: .computed("abc"), leafCertResolved: false, snapshotHasCertificateRules: true),
            "an allow that silently missed a cold certificate rule must not be cached")
    }

    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/an-undecided-allow-is-not-cached
    func testUndecidedAllowIsNotCacheable() {
        XCTAssertFalse(authResultIsCacheable(
            .allowWithUndecidedAudit(reason: .deadline),
            hashOutcome: .deadlineExceeded, leafCertResolved: true, snapshotHasCertificateRules: false),
            "an undecided ALLOW must not be cached: the identity is not yet known")
    }

    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/a-denial-is-not-cached
    func testDenyIsNotCacheable() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "c0")
        XCTAssertFalse(authResultIsCacheable(
            .deny(rule: rule, matchedIdentifier: "c0"),
            hashOutcome: .computed("c0"), leafCertResolved: true, snapshotHasCertificateRules: false),
            "a DENY must not be cached so removing the block rule takes effect on the next exec")
        XCTAssertFalse(authResultIsCacheable(
            .denyWithUndecidedAudit(reason: .deadline),
            hashOutcome: .deadlineExceeded, leafCertResolved: true, snapshotHasCertificateRules: false),
            "an undecided DENY (fail-closed posture) must not be cached either")
    }
}
