import AppKit
import Foundation
import NetworkExtension
import os.log
import SystemExtensions

private let logger = Logger(subsystem: "com.fleetdm.edr", category: "main")

/// reporter is the production Reporter: real stdout, real stderr, and the unified log. The boundary itself lives in
/// ExtensionManagerLogic so it can be tested with injected sinks (issue #687); this is only the wiring.
///
/// The log interpolations are explicitly public. Nothing routed through here is sensitive (extension identifiers ship in
/// the app bundle, and the error text names a framework condition), and leaving them to the default private treatment is
/// exactly what made the original failure reason unreadable as `<private>`.
///
/// `write(contentsOf:)` is the macOS-10.15.4+ replacement for the deprecated `write(_:)`, which traps rather than
/// returning an error on a closed or broken stderr. `try?` is right here and not a swallowed failure: a message whose
/// stderr write fails has already reached the unified log on the next line, which is the durable copy an operator
/// reading back a failed install actually goes to.
let reporter = Reporter(
    writeOut: { print($0) },
    writeErr: { try? FileHandle.standardError.write(contentsOf: Data(($0 + "\n").utf8)) },
    writeLog: { severity, message in
        switch severity {
        case .info: logger.info("\(message, privacy: .public)")
        case .warning: logger.warning("\(message, privacy: .public)")
        case .error: logger.error("\(message, privacy: .public)")
        }
    }
)

/// ExtensionManager submits activation or deactivation requests for both system extensions (the ESF
/// system extension and the network extension) and aggregates their completion outcomes through a
/// CompletionAggregator. On the activate path a successful aggregate chains into enableContentFilter and
/// then enableDNSProxy (DNS is on by default, so all three telemetry streams come up on activate); on the
/// deactivate path or any failure the host app exits with the verdict's exit code.
final class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    private let action: HostAppAction
    private var aggregator: CompletionAggregator

    init(action: HostAppAction) {
        self.action = action
        self.aggregator = CompletionAggregator(expected: HostAppExtensionID.all.count)
    }

    func run() {
        for extensionID in HostAppExtensionID.all {
            let request: OSSystemExtensionRequest = if action == .deactivate {
                OSSystemExtensionRequest.deactivationRequest(
                    forExtensionWithIdentifier: extensionID, queue: .main)
            } else {
                OSSystemExtensionRequest.activationRequest(
                    forExtensionWithIdentifier: extensionID, queue: .main)
            }
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
            reporter.progress("\(action.rawValue) request submitted for \(extensionID)")
        }
    }

    func request(
        _: OSSystemExtensionRequest,
        actionForReplacingExtension _: OSSystemExtensionProperties,
        withExtension _: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_: OSSystemExtensionRequest) {
        // On an unmanaged Mac this is the EXPECTED state, not an error, and the process stays alive while the request is
        // pending. Reporting it is what distinguishes "waiting for you in System Settings" from "hung".
        reporter.approvalPending()
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        let outcome: CompletionOutcome
        switch result {
        case .completed:
            outcome = .completed
            reporter.outcome(outcome, "\(action.rawValue) completed for \(request.identifier)")
        case .willCompleteAfterReboot:
            outcome = .willCompleteAfterReboot
            reporter.outcome(outcome, "\(action.rawValue) will complete after reboot for \(request.identifier)")
        @unknown default:
            outcome = .failed
            reporter.outcome(outcome, "Unknown result for \(request.identifier): \(result.rawValue)")
        }
        let complete = aggregator.record(outcome)
        if complete { finalizeAggregate() }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        reporter.outcome(.failed, "\(action.rawValue) failed for \(request.identifier): \(error.localizedDescription)")
        let complete = aggregator.record(.failed)
        if complete { finalizeAggregate() }
    }

    /// finalizeAggregate is invoked once the aggregator has recorded every expected outcome. Decides
    /// between chaining into enableContentFilter-then-enableDNSProxy (activate-on-success) and exiting
    /// immediately (deactivate or any failure), per the spec contract encoded in postAggregateStep. Named
    /// with the `Aggregate` suffix because NSObject already declares a `finalize()` method that this method's
    /// body has nothing to do with. The collision would be a compile error if both kept the same selector.
    private func finalizeAggregate() {
        let verdict = aggregator.verdict
        // A staged upgrade (the OS defers removing a previous extension version until reboot) leaves the network
        // extension's Mach service bound to the terminated old version, so the agent loses network + DNS telemetry until
        // the host reboots. Surface a distinct, operator-facing log line so a reboot is recognizably the fix rather than a
        // generic "will complete after reboot" info line (#399). A fresh install reports .allSucceeded and gets nothing.
        if let message = rebootRequiredMessage(for: action, verdict: verdict) {
            reporter.warning(message)
        }
        switch postAggregateStep(for: action, verdict: verdict) {
        case .enableContentFilterThenDNSProxy:
            // Enable the content filter, then chain into the DNS proxy so a freshly activated host emits all
            // three telemetry streams. Both helpers exit(EXIT_SUCCESS) on their default completion; here the
            // filter's completion enables the DNS proxy (which then exits) instead of exiting itself.
            enableContentFilter(then: { enableDNSProxy() })
        case .exitImmediately:
            exit(hostAppExitCode(for: verdict))
        }
    }
}

/// toggleLatch decides the race between a toggle's own completion handler and the watchdog armed beside it, so a
/// round-trip that lands exactly at the deadline reports one outcome rather than both.
///
/// nil until a watchdog is armed, and that is load-bearing rather than tidy. A latch is one-shot, so a single process-wide
/// instance is claimed by the FIRST terminal path and every later one loses. `activate` chains enableContentFilter into
/// enableDNSProxy in one process, so a non-optional latch made the second link lose every time: success skipped its completion
/// and the process never exited, and an error parked forever. No watchdog is armed on activate, so there is nothing to race
/// and nothing to claim.
private nonisolated(unsafe) var toggleLatch: PreferencesLatch?

/// finishToggle reports a toggle's outcome and exits, but only if this path won the race with the watchdog.
///
/// The claim has to come BEFORE the reporting, not just before the exit. An earlier version claimed the latch on the way out
/// and left `reporter` calls ahead of it, which meant a round-trip landing at the deadline printed its own result AND the
/// watchdog's timeout: exactly the "exactly one outcome" clause the requirement states. Caught in review on PR #945.
///
/// Returns Never either way, so it stays a drop-in for `exit` and no call site can fall through. A path that lost exits with the
/// watchdog's verdict rather than its own, so the status matches the single message that was printed.
private func finishToggle(_ status: Int32, _ report: () -> Void) -> Never {
    guard reportOnce(toggleLatch, report) else {
        parkUntilTheWinnerExits()
    }
    exit(status)
}

/// parkUntilTheWinnerExits blocks a path that lost the race, instead of exiting.
///
/// Exiting here looks harmless and is not. The watchdog claims the latch and THEN prints the timeout guidance, so a losing
/// callback that calls exit in between kills the process before the message the requirement demands ever reaches the operator:
/// the first fix made both outcomes print, and exiting here would have made neither. Caught in review on PR #945.
///
/// Safe to block forever because the path that won is on its way to exit(): whichever side claimed the outcome reports it and
/// terminates the process, so this thread is waiting on something guaranteed to happen.
private func parkUntilTheWinnerExits() -> Never {
    // The interval is irrelevant to correctness: the winner exits the process, so nothing here is waited on for long. It is a
    // loop rather than one long sleep only so a stuck winner shows up as a parked thread rather than an inexplicable delay.
    let parkInterval: TimeInterval = 60
    while true {
        Thread.sleep(forTimeInterval: parkInterval)
    }
}

/// claimToggleSuccess is finishToggle's half for the success paths that CHAIN rather than exit: on `activate`,
/// enableContentFilter runs enableDNSProxy after reporting. Returns false when the watchdog already reported a timeout, in which
/// case the chained work must not run and this path must stay silent.
///
/// On `activate` no watchdog is armed, so toggleLatch is nil and every link of the chain reports and continues.
private func claimToggleSuccess(_ message: String) -> Bool {
    reportOnce(toggleLatch) { reporter.progress(message) }
}

/// armPreferencesWatchdog bounds a toggle's NetworkExtension preferences round-trip (issue #905, specified by the
/// archived resilient-network-enforcement change and never built).
///
/// `loadFromPreferences` and `saveToPreferences` take a completion handler that is simply never called when the save is
/// waiting on a console-session approval that no one is there to give. The subcommand then sits in `dispatchMain()`
/// forever. That is worst exactly where it matters: `disable-dns-proxy` is the operator's recovery lever for a host
/// whose DNS our own proxy has broken, and it is reached over SSH, which is the case with no console session.
private func armPreferencesWatchdog(for action: HostAppAction) {
    let latch = PreferencesLatch()
    toggleLatch = latch
    DispatchQueue.global().asyncAfter(deadline: .now() + defaultPreferencesTimeout) {
        guard latch.expire() else { return }
        reporter.failure(preferencesTimeoutMessage(for: action, timeout: defaultPreferencesTimeout))
        exit(EXIT_FAILURE)
    }
}

private func enableContentFilter(then completion: @escaping () -> Void = { exit(EXIT_SUCCESS) }) {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error {
            finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to load filter preferences: \(error.localizedDescription)") }
        }
        print("Loaded filter preferences, isEnabled=\(NEFilterManager.shared().isEnabled)")

        let filterConfig = NEFilterProviderConfiguration()
        filterConfig.filterSockets = activateFilterConfig.filterSockets
        filterConfig.filterPackets = activateFilterConfig.filterPackets

        NEFilterManager.shared().providerConfiguration = filterConfig
        NEFilterManager.shared().localizedDescription = activateFilterConfig.localizedDescription
        NEFilterManager.shared().isEnabled = activateFilterConfig.isEnabled

        print("Saving filter preferences...")
        NEFilterManager.shared().saveToPreferences { error in
            if let error {
                finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to save filter preferences: \(error.localizedDescription)") }
            }
            if claimToggleSuccess("Content filter enabled successfully") {
                completion()
            }
        }
    }
}

private func enableDNSProxy(then completion: @escaping () -> Void = { exit(EXIT_SUCCESS) }) {
    NEDNSProxyManager.shared().loadFromPreferences { error in
        if let error {
            finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to load DNS proxy preferences: \(error.localizedDescription)") }
        }

        let proxyConfig = NEDNSProxyProviderProtocol()
        proxyConfig.providerBundleIdentifier = activateDNSProxyConfig.providerBundleIdentifier

        NEDNSProxyManager.shared().providerProtocol = proxyConfig
        NEDNSProxyManager.shared().localizedDescription = activateDNSProxyConfig.localizedDescription
        NEDNSProxyManager.shared().isEnabled = activateDNSProxyConfig.isEnabled

        NEDNSProxyManager.shared().saveToPreferences { error in
            if let error {
                finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to save DNS proxy preferences: \(error.localizedDescription)") }
            }
            if claimToggleSuccess("DNS proxy enabled successfully") {
                completion()
            }
        }
    }
}

private func disableContentFilter() {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error {
            finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to load filter preferences: \(error.localizedDescription)") }
        }
        NEFilterManager.shared().isEnabled = false
        NEFilterManager.shared().saveToPreferences { error in
            if let error {
                finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to disable filter: \(error.localizedDescription)") }
            }
            finishToggle(EXIT_SUCCESS) { reporter.progress("Content filter disabled") }
        }
    }
}

private func disableDNSProxy() {
    NEDNSProxyManager.shared().loadFromPreferences { error in
        if let error {
            finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to load DNS proxy preferences: \(error.localizedDescription)") }
        }
        NEDNSProxyManager.shared().isEnabled = false
        NEDNSProxyManager.shared().saveToPreferences { error in
            if let error {
                finishToggle(EXIT_FAILURE) { reporter.failure("ERROR: Failed to disable DNS proxy: \(error.localizedDescription)") }
            }
            finishToggle(EXIT_SUCCESS) { reporter.progress("DNS proxy disabled") }
        }
    }
}

/// runNotifyMode keeps the host app alive as a long-running
/// accessory NSApplication, vending the block-notification XPC
/// service and presenting NSAlert modals on every accepted
/// AUTH_EXEC-denied notification. Distinct from the other CLI
/// modes (one-shot extension activation, filter toggles) which run
/// dispatchMain and exit on completion. The notify surface has no
/// terminal state by design.
///
/// Runs as `.accessory` so a modal can appear without the app
/// claiming a Dock icon. `app.run()` (not dispatchMain()) is what
/// AppKit needs to dispatch input events that NSAlert depends on.
private func runNotifyMode() {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let presenter = BlockAlertPresenterAppKit()
    let listener = NotificationListener(presenter: presenter)
    listener.start()
    logger.info("Application Control notification surface running on \(blockNotificationServiceName, privacy: .public)")
    // withExtendedLifetime keeps the listener alive for the duration
    // of the AppKit run loop. ARC is otherwise free to drop a local
    // whose only remaining "uses" are inside [weak self] event
    // handlers, which would silently take the XPC surface offline in
    // optimised builds. Caught by Gemini and Copilot on PR #157.
    withExtendedLifetime(listener) {
        app.run()
    }
}

let positionalArgs = Array(CommandLine.arguments.dropFirst())
guard let action = validateHostAppArgs(positionalArgs) else {
    // Malformed CLI invocation: unrecognised subcommand, empty argument, OR extra positional arguments
    // after the subcommand. All three collapse to the same fail-loudly contract: print usage to stderr,
    // exit non-zero, so an operator's typo or shell-expansion bug can't silently become an unintended
    // activation. `write(contentsOf:)` is the macOS-10.15.4+ replacement for the deprecated `write(_:)`;
    // try? is appropriate here because we're already on the exit-FAILURE path and have nothing to do
    // about a stderr write failure.
    try? FileHandle.standardError.write(contentsOf: Data(hostAppUsage().utf8))
    try? FileHandle.standardError.write(contentsOf: Data("\n".utf8))
    exit(EXIT_FAILURE)
}

switch action {
case .enableFilter:
    print("Enabling content filter...")
    armPreferencesWatchdog(for: .enableFilter)
    enableContentFilter()
    dispatchMain()
case .disableFilter:
    print("Disabling content filter...")
    armPreferencesWatchdog(for: .disableFilter)
    disableContentFilter()
    dispatchMain()
case .enableDNSProxy:
    print("Enabling DNS proxy...")
    armPreferencesWatchdog(for: .enableDNSProxy)
    enableDNSProxy()
    dispatchMain()
case .disableDNSProxy:
    print("Disabling DNS proxy...")
    armPreferencesWatchdog(for: .disableDNSProxy)
    disableDNSProxy()
    dispatchMain()
case .notify:
    print("Starting Fleet EDR notification surface...")
    runNotifyMode()
case .activate, .deactivate:
    let manager = ExtensionManager(action: action)
    manager.run()
    dispatchMain()
}
