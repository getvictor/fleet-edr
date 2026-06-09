import XCTest
@testable import EDRExtensionLogic

/// Unit-test surface for the host-app-extension-manager capability. Each scenario in
/// openspec/specs/host-app-extension-manager/spec.md is covered by one XCTest function pinned by a
/// `// spec:<canonical-id>` marker comment. The OSSystemExtensionRequest delegate callbacks, the
/// NEFilterManager.shared() / NEDNSProxyManager.shared() save flows, and macOS's reboot-restore of
/// NetworkExtension preferences are all owned by Apple frameworks + the OS; the host-app's contribution to
/// each scenario is the pure-logic contract these tests pin (subcommand → intents, completion outcomes →
/// aggregate verdict → exit code, persisted-config shape). The framework-side enforcement is exercised at
/// the system / VM rehearsal layer per docs/testing-strategy.md; a divergence between this contract and
/// production main.swift is what the rehearsal layer catches.
final class HostAppExtensionManagerTests: XCTestCase {

    // MARK: - Requirement: Activate subcommand registers both extensions and enables the filter

    // swiftlint:disable:next line_length
    // spec:host-app-extension-manager/activate-subcommand-registers-both-extensions-and-enables-the-filter/first-time-activation-on-an-unconfigured-machine
    func testActivateSubmitsTwoActivationRequestsAndEnablesFilterAndDNSProxyOnSuccess() {
        // The activate subcommand expands to one activation request per documented extension id followed
        // by a content-filter enable AND a DNS-proxy enable (DNS is on by default). main.swift wires the
        // per-request submission to OSSystemExtensionManager and the post-aggregate enables to
        // NEFilterManager / NEDNSProxyManager saveToPreferences(); both fire the user-approval dialog the
        // first time on an unconfigured machine. The "approval pending" reporting clause is owned by
        // main.swift's `requestNeedsUserApproval` delegate callback (logs to os.log so an operator tailing
        // the unified log sees the pending state) and is verified at the VM rehearsal layer; the spec
        // contract here is the ordered intent list.
        let plan = intents(for: .activate)
        XCTAssertEqual(plan, [
            .submitActivationRequest(extensionID: HostAppExtensionID.endpointSecurity),
            .submitActivationRequest(extensionID: HostAppExtensionID.networkExtension),
            .setContentFilterEnabled(true),
            .setDNSProxyEnabled(true)
        ])

        // Once both extension requests report .completed, the post-aggregate step is
        // .enableContentFilterThenDNSProxy and the host app's eventual exit code is EXIT_SUCCESS.
        var agg = CompletionAggregator(expected: 2)
        XCTAssertFalse(agg.record(.completed))
        XCTAssertTrue(agg.record(.completed))
        XCTAssertEqual(agg.verdict, .allSucceeded)
        XCTAssertEqual(postAggregateStep(for: .activate, verdict: agg.verdict), .enableContentFilterThenDNSProxy)
        XCTAssertEqual(hostAppExitCode(for: agg.verdict), Int32(EXIT_SUCCESS))
    }

    // swiftlint:disable:next line_length
    // spec:host-app-extension-manager/activate-subcommand-registers-both-extensions-and-enables-the-filter/re-activation-when-extensions-are-already-approved
    func testReactivationProducesSameIntentsAndReliesOnReplaceActionPolicy() {
        // Re-activation expands to the same intent list as first-time activation; the difference is
        // OS-side. When the same bundle id is already registered, OSSystemExtensionManager invokes the
        // `request(_:actionForReplacingExtension:withExtension:)` delegate callback to ask "drop the old
        // copy?" - main.swift returns `.replace`, so the running extensions are swapped for the on-disk
        // copy without a deactivate-then-activate round trip. The replace policy is a single value pinned
        // in main.swift; this test pins the intent shape (same as first-time) and notes the replacement
        // policy lives there.
        let plan = intents(for: .activate)
        XCTAssertEqual(plan.first, .submitActivationRequest(extensionID: HostAppExtensionID.endpointSecurity))
        XCTAssertEqual(plan.dropFirst().first, .submitActivationRequest(extensionID: HostAppExtensionID.networkExtension))
        // Activate enables the filter then the DNS proxy, so the plan ends with the DNS-proxy enable and still
        // contains the content-filter enable.
        XCTAssertEqual(plan.last, .setDNSProxyEnabled(true))
        XCTAssertTrue(plan.contains(.setContentFilterEnabled(true)))
        // The exit code for a clean re-activation is EXIT_SUCCESS - same aggregate verdict as the
        // first-time case (both delegates return .completed on a re-activation against approved
        // extensions).
        var agg = CompletionAggregator(expected: 2)
        agg.record(.completed)
        agg.record(.completed)
        XCTAssertEqual(hostAppExitCode(for: agg.verdict), Int32(EXIT_SUCCESS))
    }

    // MARK: - Requirement: Deactivate subcommand removes both extensions

    // spec:host-app-extension-manager/deactivate-subcommand-removes-both-extensions/deactivating-an-active-install
    func testDeactivateSubmitsTwoDeactivationRequestsAndExitsCleanlyOnCompletion() {
        // The deactivate subcommand submits a deactivation request per extension id and does NOT chain
        // into a filter toggle (the spec says the extensions stop running, not the filter; the OS
        // tears the filter down as a side effect of the network extension uninstall).
        let plan = intents(for: .deactivate)
        XCTAssertEqual(plan, [
            .submitDeactivationRequest(extensionID: HostAppExtensionID.endpointSecurity),
            .submitDeactivationRequest(extensionID: HostAppExtensionID.networkExtension)
        ])
        // No setContentFilterEnabled in the deactivate plan.
        XCTAssertFalse(plan.contains(where: { intent in
            if case .setContentFilterEnabled = intent { return true } else { return false }
        }))

        // Both deactivations complete -> aggregate verdict is .allSucceeded, post-step is .exitImmediately,
        // exit code is EXIT_SUCCESS.
        var agg = CompletionAggregator(expected: 2)
        agg.record(.completed)
        agg.record(.completed)
        XCTAssertEqual(postAggregateStep(for: .deactivate, verdict: agg.verdict), .exitImmediately)
        XCTAssertEqual(hostAppExitCode(for: agg.verdict), Int32(EXIT_SUCCESS))
    }

    // spec:host-app-extension-manager/deactivate-subcommand-removes-both-extensions/one-of-the-two-deactivations-fails
    func testDeactivateReportsFailureWhenAnyExtensionDeactivationFails() {
        // The spec's "one of the two deactivations reports an error" clause: the aggregator must surface
        // .anyFailed even if the OTHER deactivation succeeded. The exit code is EXIT_FAILURE per the
        // "exit status MUST reflect failure" requirement-body clause.
        var agg = CompletionAggregator(expected: 2)
        agg.record(.completed)
        agg.record(.failed)
        XCTAssertEqual(agg.verdict, .anyFailed)
        XCTAssertEqual(hostAppExitCode(for: agg.verdict), Int32(EXIT_FAILURE))

        // Order independence: failure-first then success still produces .anyFailed.
        var agg2 = CompletionAggregator(expected: 2)
        agg2.record(.failed)
        agg2.record(.completed)
        XCTAssertEqual(agg2.verdict, .anyFailed)
        XCTAssertEqual(hostAppExitCode(for: agg2.verdict), Int32(EXIT_FAILURE))
    }

    // MARK: - Requirement: Filter enable and disable subcommands

    // spec:host-app-extension-manager/filter-enable-and-disable-subcommands/disable-the-filter-without-removing-the-extension
    func testDisableFilterTogglesOnlyTheFilterAndDoesNotTouchExtensions() {
        // The spec's "MUST NOT activate or deactivate either extension" clause is encoded in the intent
        // shape: disable-filter's plan contains ONLY a setContentFilterEnabled(false) intent. No
        // submitActivationRequest, no submitDeactivationRequest, no DNS-proxy toggle.
        let plan = intents(for: .disableFilter)
        XCTAssertEqual(plan, [.setContentFilterEnabled(false)])
        XCTAssertFalse(plan.contains(where: { intent in
            switch intent {
            case .submitActivationRequest, .submitDeactivationRequest: return true
            default: return false
            }
        }))
    }

    // spec:host-app-extension-manager/filter-enable-and-disable-subcommands/re-enable-the-filter
    func testEnableFilterTogglesOnlyTheFilterToTrue() {
        // Symmetric to disable-filter: enable-filter's intent list is exactly setContentFilterEnabled(true)
        // and nothing else. Once main.swift's enableContentFilter() returns, new outbound flows reach the
        // active network extension's filter; verifying that runtime claim is the system / VM layer's job.
        let plan = intents(for: .enableFilter)
        XCTAssertEqual(plan, [.setContentFilterEnabled(true)])
    }

    // MARK: - Requirement: DNS proxy enable and disable subcommands

    // spec:host-app-extension-manager/dns-proxy-enable-and-disable-subcommands/enable-dns-proxy-on-top-of-an-active-filter
    func testEnableDNSProxyTouchesOnlyDNSProxyAndLeavesFilterAlone() {
        // The spec's "MUST NOT toggle" cross-feature clause: enable-dns-proxy's intent list contains ONLY
        // setDNSProxyEnabled(true). No content-filter intent in the list = the filter's prior state is
        // preserved (the host app never calls NEFilterManager.shared() in this subcommand).
        let plan = intents(for: .enableDNSProxy)
        XCTAssertEqual(plan, [.setDNSProxyEnabled(true)])
        XCTAssertFalse(plan.contains(where: { intent in
            if case .setContentFilterEnabled = intent { return true } else { return false }
        }))
    }

    // spec:host-app-extension-manager/dns-proxy-enable-and-disable-subcommands/disable-dns-proxy-without-affecting-other-state
    func testDisableDNSProxyTouchesOnlyDNSProxyAndLeavesFilterAlone() {
        // Symmetric to enable-dns-proxy: the disable-dns-proxy intent list contains only
        // setDNSProxyEnabled(false); the filter's enabled bit is untouched by this subcommand.
        let plan = intents(for: .disableDNSProxy)
        XCTAssertEqual(plan, [.setDNSProxyEnabled(false)])
        XCTAssertFalse(plan.contains(where: { intent in
            if case .setContentFilterEnabled = intent { return true } else { return false }
        }))
    }

    // MARK: - Requirement: Configuration persists across reboots

    // spec:host-app-extension-manager/configuration-persists-across-reboots/reboot-recovers-active-configuration
    func testActivateConfigurationsPinIsEnabledTrueSoMacOSRestoresThemOnReboot() {
        // macOS persists NEFilterManager / NEDNSProxyManager preferences across reboots automatically; the
        // host-app's contribution is calling saveToPreferences() with isEnabled=true on each. The persisted
        // shape is what this test pins: a FilterConfigIntent + DNSProxyConfigIntent with isEnabled=true
        // and the documented provider configuration. When the host comes back up, the OS reloads these
        // preferences, sees isEnabled=true, and reattaches the extensions to the kernel's filter + DNS-
        // proxy plumbing - at which point event capture resumes without operator action. The OS-side
        // restore is verified at the system / VM rehearsal layer.
        XCTAssertTrue(activateFilterConfig.isEnabled,
                      "the saved content-filter preference must be isEnabled=true so macOS restores the filter on reboot")
        XCTAssertTrue(activateFilterConfig.filterSockets,
                      "socket filtering must be persisted so the network extension sees flow events post-reboot")
        XCTAssertEqual(activateFilterConfig.localizedDescription, "Fleet EDR Network Monitor",
                       "the System Settings -> Network -> Filters label must be the documented Fleet EDR copy")

        XCTAssertTrue(activateDNSProxyConfig.isEnabled,
                      "the saved DNS-proxy preference must be isEnabled=true so macOS restores DNS capture on reboot")
        XCTAssertEqual(activateDNSProxyConfig.providerBundleIdentifier, HostAppExtensionID.networkExtension,
                       "the DNS-proxy provider must point at the network extension's bundle id so macOS knows which extension to reattach")
    }

    // MARK: - Requirement: Activation reports completion outcomes

    // spec:host-app-extension-manager/activation-reports-completion-outcomes/one-extension-completes-immediately-and-the-other-needs-a-reboot
    func testRebootRequiredAggregateExitsSuccessSoOperatorDoesNotRetry() {
        // Spec asserts: when one extension reports .completed and the other reports
        // .willCompleteAfterReboot, the host app reports reboot-required AND exits successfully (so the
        // activation is not retried prematurely). Aggregator with one of each outcome produces
        // .rebootRequired; the exit code maps to EXIT_SUCCESS.
        var agg = CompletionAggregator(expected: 2)
        agg.record(.completed)
        agg.record(.willCompleteAfterReboot)
        XCTAssertEqual(agg.verdict, .rebootRequired)
        XCTAssertEqual(hostAppExitCode(for: agg.verdict), Int32(EXIT_SUCCESS),
                       "reboot-required path must exit success so the activation is not retried prematurely")

        // Order independence: reboot-first then completed yields the same verdict + exit code.
        var agg2 = CompletionAggregator(expected: 2)
        agg2.record(.willCompleteAfterReboot)
        agg2.record(.completed)
        XCTAssertEqual(agg2.verdict, .rebootRequired)
        XCTAssertEqual(hostAppExitCode(for: agg2.verdict), Int32(EXIT_SUCCESS))
    }

    // spec:host-app-extension-manager/activation-reports-completion-outcomes/an-activation-request-errors
    func testFailedActivationExitsNonZero() {
        // A single .failed outcome forces the aggregate to .anyFailed and the exit code to EXIT_FAILURE,
        // regardless of how many other requests reported. Failure dominates the verdict (`anyFailed`
        // takes precedence over both `rebootRequired` and `allSucceeded`).
        var agg = CompletionAggregator(expected: 2)
        agg.record(.failed)
        agg.record(.willCompleteAfterReboot)
        XCTAssertEqual(agg.verdict, .anyFailed,
                       "any failure dominates the aggregate, even alongside a will-complete-after-reboot success")
        XCTAssertEqual(hostAppExitCode(for: agg.verdict), Int32(EXIT_FAILURE))
        // .anyFailed also short-circuits the post-step regardless of subcommand: activate does NOT chain
        // into filter-enable on failure.
        XCTAssertEqual(postAggregateStep(for: .activate, verdict: agg.verdict), .exitImmediately)
    }

    // MARK: - Action parsing (supporting coverage)

    func testParseHostAppActionRecognisesEveryDocumentedSubcommand() {
        // nil argv defaults to .activate (the documented no-subcommand behavior); every recognised raw
        // value resolves to the matching enum case.
        XCTAssertEqual(parseHostAppAction(nil), .activate)
        XCTAssertEqual(parseHostAppAction("activate"), .activate)
        XCTAssertEqual(parseHostAppAction("deactivate"), .deactivate)
        XCTAssertEqual(parseHostAppAction("enable-filter"), .enableFilter)
        XCTAssertEqual(parseHostAppAction("disable-filter"), .disableFilter)
        XCTAssertEqual(parseHostAppAction("enable-dns-proxy"), .enableDNSProxy)
        XCTAssertEqual(parseHostAppAction("disable-dns-proxy"), .disableDNSProxy)
        XCTAssertEqual(parseHostAppAction("notify"), .notify)
    }

    // MARK: - Requirement: Subcommand parsing fails loudly on unknown input

    // spec:host-app-extension-manager/subcommand-parsing-fails-loudly-on-unknown-input/unknown-subcommand-exits-with-usage-and-non-zero-status
    func testMalformedCLIInvocationReturnsNilSoMainSwiftCanPrintUsageAndExit() {
        // The spec scenario asserts the host app prints usage + exits non-zero for ANY malformed
        // invocation: typo / deprecated name (unrecognised subcommand), empty subcommand argument
        // (`edr ""`), OR extra positional arguments after a valid subcommand (`edr deactivate typo`).
        // The parsing side of that contract is `validateHostAppArgs` returning nil; main.swift's
        // top-level `guard let action = ... else { write(hostAppUsage()); exit(EXIT_FAILURE) }` is what
        // converts the nil into the documented stderr + non-zero exit.

        // Unrecognised subcommand (the original case): typo, near-miss, case-mismatch.
        XCTAssertNil(parseHostAppAction("unknown-subcommand"),
                     "an unrecognised subcommand must NOT silently default to activate")
        XCTAssertNil(parseHostAppAction("deactvate"),
                     "a near-miss typo of deactivate must NOT silently activate")
        XCTAssertNil(parseHostAppAction("ACTIVATE"),
                     "case-sensitivity: ALL-CAPS subcommand is unrecognised")

        // Empty subcommand argument (`edr ""`): typically a shell-expansion bug; fail loudly.
        XCTAssertNil(parseHostAppAction(""),
                     "an empty argv[1] must NOT silently default to activate (likely a shell-expansion bug)")
        XCTAssertNil(validateHostAppArgs([""]),
                     "argv shaped as a single empty positional must be rejected")

        // Extra positional arguments after a valid subcommand: `edr deactivate typo` is the realistic
        // footgun; the tail must NOT be silently dropped.
        XCTAssertNil(validateHostAppArgs(["deactivate", "typo"]),
                     "extra positional arguments must NOT be silently dropped")
        XCTAssertNil(validateHostAppArgs(["activate", "extra1", "extra2"]),
                     "any number of extra positionals after the subcommand is malformed")

        // No-positional and single-valid-positional remain the happy paths.
        XCTAssertEqual(validateHostAppArgs([]), .activate,
                       "no positional argument is the documented no-subcommand default")
        XCTAssertEqual(validateHostAppArgs(["deactivate"]), .deactivate,
                       "a single recognised positional resolves to its enum case")

        // The usage message lists every documented subcommand so an operator sees the supported set.
        let usage = hostAppUsage()
        for action in HostAppAction.allCases {
            XCTAssertTrue(usage.contains(action.rawValue),
                          "usage message must list every documented subcommand; missing \(action.rawValue)")
        }
        XCTAssertTrue(usage.lowercased().contains("usage"),
                      "usage message must start with an operator-recognisable 'Usage:' header")
        XCTAssertTrue(usage.lowercased().contains("extra positional"),
                      "usage message must call out the extra-positional rejection rule")
    }
}
