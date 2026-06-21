// DNSForwardCompletion tests: pin the deadline-vs-receive race semantics. onResolve must run exactly once, and the atomic
// claim must guarantee that once the receive path claims a forward the deadline can no longer reclassify it as a failure
// (the TOCTOU hole Qodo flagged on PR #471).

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class DNSForwardCompletionTests: XCTestCase {
    func testReceiveWinsThenDeadlineIsNoOp() {
        var outcomes: [Bool] = []
        let c = DNSForwardCompletion { outcomes.append($0) }
        XCTAssertTrue(c.claimResponse())     // receive path claims first
        c.failIfPending()                    // deadline fires after the claim -> must be a no-op
        c.resolveResponse(ok: true)          // receive finalizes the success
        XCTAssertEqual(outcomes, [true])     // resolved exactly once, as success (not reclassified to failure)
    }

    func testDeadlineWinsThenReceiveCannotClaim() {
        var outcomes: [Bool] = []
        let c = DNSForwardCompletion { outcomes.append($0) }
        c.failIfPending()                    // deadline wins
        XCTAssertFalse(c.claimResponse())    // late receive path cannot claim -> it must bail without touching the flow
        c.resolveResponse(ok: true)          // and even if mis-called, it is a no-op
        XCTAssertEqual(outcomes, [false])    // resolved exactly once, as failure
    }

    func testResolveOnlyFiresOnce() {
        var count = 0
        let c = DNSForwardCompletion { _ in count += 1 }
        XCTAssertTrue(c.claimResponse())
        c.resolveResponse(ok: true)
        c.resolveResponse(ok: false)         // double finalize is ignored
        c.failIfPending()                    // and the deadline after done is ignored
        XCTAssertEqual(count, 1)
    }

    func testResolveResponseWithoutClaimIsNoOp() {
        var outcomes: [Bool] = []
        let c = DNSForwardCompletion { outcomes.append($0) }
        c.resolveResponse(ok: true)          // never claimed -> cannot finalize
        XCTAssertTrue(outcomes.isEmpty)
        c.failIfPending()                    // still pending, so the deadline can resolve it
        XCTAssertEqual(outcomes, [false])
    }
}
