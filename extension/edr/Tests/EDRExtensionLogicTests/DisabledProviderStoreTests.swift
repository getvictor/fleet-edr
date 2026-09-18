import Foundation
@testable import EDRExtensionLogic
import XCTest

/// Tests for what a restarted extension remembers about providers an operator switched off (issue #1078).
///
/// The liveness report is rebuilt per extension process, and a provider that is disabled never starts and so never stops. Without a
/// memory, `disabled` survives only until the next restart and a rebooted host reports the provider absent again, which is the state
/// the issue reported.
final class DisabledProviderStoreTests: XCTestCase {
    private func store() -> (DisabledProviderStore, String) {
        let path = NSTemporaryDirectory() + "disabled-providers-\(UUID().uuidString).json"
        addTeardownBlock { try? FileManager.default.removeItem(atPath: path) }
        return (DisabledProviderStore(storagePath: path), path)
    }

    // spec:agent-status-reporting/network-extension-health-reflects-capture-provider-liveness/a-disabled-provider-survives-a-restart
    func testWhatWasSavedIsWhatLoads() {
        let (subject, _) = store()
        XCTAssertTrue(subject.save(["dns_proxy"]))
        XCTAssertEqual(subject.load(), ["dns_proxy"])

        // Re-enabling clears it, which is how a stale entry stops being remembered.
        XCTAssertTrue(subject.save([]))
        XCTAssertTrue(subject.load().isEmpty)
    }

    /// A file that is missing or unreadable remembers NOTHING rather than guessing. A provider wrongly thought disabled is corrected
    /// within seconds by its start callback; one wrongly thought running would be a false claim that a consumer contradicts against
    /// arriving telemetry, so this is the direction to fail in.
    func testAnUnreadableFileRemembersNothing() {
        let (subject, path) = store()
        XCTAssertTrue(subject.load().isEmpty, "nothing has been saved yet")

        try? Data("not json".utf8).write(to: URL(fileURLWithPath: path))
        XCTAssertTrue(subject.load().isEmpty, "a corrupt file is not a claim about any provider")
    }

    /// The reporter seeds itself from the store before its first publish, which is the whole point: a fresh process has no callback
    /// telling it that a provider is switched off.
    func testAReporterStartsKnowingWhatWasSwitchedOff() {
        let (subject, path) = store()
        XCTAssertTrue(subject.save(["dns_proxy"]))

        var published: [ProviderStatusPayload] = []
        let reporter = ProviderStatusReporter(
            broadcast: { _ in },
            serialize: { payload in
                published.append(payload)
                return Data()
            },
            disabledStore: DisabledProviderStore(storagePath: path)
        )
        reporter.publish()

        XCTAssertEqual(published.last?.providers["dns_proxy"], "disabled",
                       "a restarted extension still reports the provider its operator turned off")
    }

    /// And a provider that is actually running corrects the memory rather than keeping it, so a proxy re-enabled while the extension
    /// was down does not report disabled once it comes back.
    func testAStartingProviderClearsTheMemory() {
        let (subject, path) = store()
        XCTAssertTrue(subject.save(["dns_proxy"]))

        let reporter = ProviderStatusReporter(broadcast: { _ in }, serialize: { _ in Data() },
                                              disabledStore: DisabledProviderStore(storagePath: path))
        reporter.recordStarted(.dnsProxy)

        XCTAssertTrue(subject.load().isEmpty, "a capturing provider is not switched off, whatever an earlier process recorded")
    }
}
