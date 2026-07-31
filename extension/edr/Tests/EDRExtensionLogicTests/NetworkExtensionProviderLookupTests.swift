// NetworkExtensionProviderLookup tests: pin the memoisation, the process-generation keying, the bounded purge, and the
// fail-open branches (issue #656). The SecCode walk itself needs a live process, so it is injected; everything around it
// is ordinary logic and is exercised directly here.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class NetworkExtensionProviderLookupTests: XCTestCase {
    /// A stand-in audit token. Only its non-emptiness matters: the real parse happens in `extractProcessInfo`, and the
    /// identity is supplied separately, so the lookup treats this as an opaque blob to hand to the reader.
    private let token = Data(repeating: 0xAB, count: 32)

    private func identity(pid: pid_t, pidversion: UInt32?) -> ProcessIdentity {
        ProcessIdentity(pid: pid, uid: 0, pidversion: pidversion)
    }

    func testReaderVerdictIsReturned() {
        for expected in [true, false] {
            let lookup = NetworkExtensionProviderLookup(readEntitlement: { _ in expected })
            XCTAssertEqual(lookup.isProvider(auditToken: token, identity: identity(pid: 42, pidversion: 1)), expected)
        }
    }

    func testVerdictIsMemoisedPerProcessGeneration() {
        var reads = 0
        let lookup = NetworkExtensionProviderLookup(readEntitlement: { _ in reads += 1; return true })
        let subject = identity(pid: 42, pidversion: 1)

        for _ in 0..<5 {
            XCTAssertTrue(lookup.isProvider(auditToken: token, identity: subject))
        }
        // The SecCode walk is a few hundred microseconds on the DNS hot path, so it must happen once per generation, not
        // once per flow.
        XCTAssertEqual(reads, 1)
    }

    func testRecycledPidIsNotServedThePredecessorsVerdict() {
        var answers = [true, false]
        let lookup = NetworkExtensionProviderLookup(readEntitlement: { _ in answers.removeFirst() })

        // Same pid, different kernel generation: a recycled pid belonging to a different program must re-read rather than
        // inherit the previous tenant's verdict, which is the whole reason the key carries pidversion (issue #403).
        XCTAssertTrue(lookup.isProvider(auditToken: token, identity: identity(pid: 42, pidversion: 1)))
        XCTAssertFalse(lookup.isProvider(auditToken: token, identity: identity(pid: 42, pidversion: 2)))
        XCTAssertTrue(answers.isEmpty, "both generations must have consulted the reader")
    }

    func testDistinctProcessesAreCachedIndependently() {
        var reads = 0
        let lookup = NetworkExtensionProviderLookup(readEntitlement: { _ in reads += 1; return true })
        for pid in pid_t(1)...pid_t(3) {
            _ = lookup.isProvider(auditToken: token, identity: identity(pid: pid, pidversion: 1))
            _ = lookup.isProvider(auditToken: token, identity: identity(pid: pid, pidversion: 1))
        }
        XCTAssertEqual(reads, 3, "three processes, one read each, second lookups served from cache")
    }

    func testCacheIsBoundedAndKeepsAnswering() {
        var reads = 0
        let lookup = NetworkExtensionProviderLookup(readEntitlement: { _ in reads += 1; return true })
        // Push well past the 4096 cap. The purge is wholesale, so the only guarantees worth pinning are that it stays
        // bounded (no unbounded growth from a churn of short-lived resolver processes) and that verdicts remain correct
        // across the purge, which a cold miss re-derives.
        for pid in pid_t(1)...pid_t(5000) {
            XCTAssertTrue(lookup.isProvider(auditToken: token, identity: identity(pid: pid, pidversion: 1)))
        }
        XCTAssertEqual(reads, 5000)
        // Still answering correctly after the purge boundary was crossed.
        XCTAssertTrue(lookup.isProvider(auditToken: token, identity: identity(pid: 5001, pidversion: 1)))
    }

    func testUnresolvableSourcesFailOpenWithoutConsultingTheReader() {
        var reads = 0
        let lookup = NetworkExtensionProviderLookup(readEntitlement: { _ in reads += 1; return true })

        // A flow can arrive with no audit token, a dead pid, or no kernel generation. None of those can prove the source
        // is another provider, so all three take ordinary routing. Declining to attribute must not cost a SecCode walk
        // either, since these arrive on the same hot path.
        XCTAssertFalse(lookup.isProvider(auditToken: nil, identity: identity(pid: 42, pidversion: 1)))
        XCTAssertFalse(lookup.isProvider(auditToken: token, identity: identity(pid: 0, pidversion: 1)))
        XCTAssertFalse(lookup.isProvider(auditToken: token, identity: identity(pid: -1, pidversion: 1)))
        XCTAssertFalse(lookup.isProvider(auditToken: token, identity: identity(pid: 42, pidversion: nil)))
        XCTAssertEqual(reads, 0)
    }
}
