// AuthResultCacheableTests pins authResultIsCacheable: the pure mapping from an AuthDecision to the kernel-cache flag the
// AUTH_EXEC wire side passes to es_respond_auth_result (#209). The wire call lives in ESFSubscriber.swift (excluded from this
// target because it imports EndpointSecurity), so this is the only layer that can pin the contract below the system / VM run.
// A decided ALLOW is cacheable (the verdict is a function of the stable identity tuple + the active snapshot, and the store
// flushes the kernel cache on every snapshot swap); undecided ALLOWs and every DENY are not.

@testable import EDRExtensionLogic
import XCTest

final class AuthResultCacheableTests: XCTestCase {
    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/a-decided-allow-is-cached-at-the-kernel
    func testDecidedAllowIsCacheable() {
        XCTAssertTrue(authResultIsCacheable(.allow), "a decided ALLOW must be pinned into the kernel AUTH cache")
    }

    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/an-undecided-allow-is-not-cached
    func testUndecidedAllowIsNotCacheable() {
        XCTAssertFalse(
            authResultIsCacheable(.allowWithUndecidedAudit(reason: .deadline)),
            "an undecided ALLOW must not be cached: the identity is not yet known, so caching would defeat the deferred fill"
        )
    }

    // spec:extension-application-control/decided-allow-is-cached-and-flushed-on-snapshot-replacement/a-denial-is-not-cached
    func testDenyIsNotCacheable() {
        let rule = makeRule(ruleType: ApplicationControlRuleType.cdhash, identifier: "c0")
        XCTAssertFalse(
            authResultIsCacheable(.deny(rule: rule, matchedIdentifier: "c0")),
            "a DENY must not be cached so removing the block rule takes effect on the next exec"
        )
        XCTAssertFalse(
            authResultIsCacheable(.denyWithUndecidedAudit(reason: .deadline)),
            "an undecided DENY (fail-closed posture) must not be cached either"
        )
    }
}
