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

private func enableContentFilter(then completion: @escaping () -> Void = { exit(EXIT_SUCCESS) }) {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error {
            reporter.failure("ERROR: Failed to load filter preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
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
                reporter.failure("ERROR: Failed to save filter preferences: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            reporter.progress("Content filter enabled successfully")
            completion()
        }
    }
}

private func enableDNSProxy(then completion: @escaping () -> Void = { exit(EXIT_SUCCESS) }) {
    NEDNSProxyManager.shared().loadFromPreferences { error in
        if let error {
            reporter.failure("ERROR: Failed to load DNS proxy preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
        }

        let proxyConfig = NEDNSProxyProviderProtocol()
        proxyConfig.providerBundleIdentifier = activateDNSProxyConfig.providerBundleIdentifier

        NEDNSProxyManager.shared().providerProtocol = proxyConfig
        NEDNSProxyManager.shared().localizedDescription = activateDNSProxyConfig.localizedDescription
        NEDNSProxyManager.shared().isEnabled = activateDNSProxyConfig.isEnabled

        NEDNSProxyManager.shared().saveToPreferences { error in
            if let error {
                reporter.failure("ERROR: Failed to save DNS proxy preferences: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            reporter.progress("DNS proxy enabled successfully")
            completion()
        }
    }
}

private func disableContentFilter() {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error {
            reporter.failure("ERROR: Failed to load filter preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
        }
        NEFilterManager.shared().isEnabled = false
        NEFilterManager.shared().saveToPreferences { error in
            if let error {
                reporter.failure("ERROR: Failed to disable filter: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            reporter.progress("Content filter disabled")
            exit(EXIT_SUCCESS)
        }
    }
}

private func disableDNSProxy() {
    NEDNSProxyManager.shared().loadFromPreferences { error in
        if let error {
            reporter.failure("ERROR: Failed to load DNS proxy preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
        }
        NEDNSProxyManager.shared().isEnabled = false
        NEDNSProxyManager.shared().saveToPreferences { error in
            if let error {
                reporter.failure("ERROR: Failed to disable DNS proxy: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            reporter.progress("DNS proxy disabled")
            exit(EXIT_SUCCESS)
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
    enableContentFilter()
    dispatchMain()
case .disableFilter:
    print("Disabling content filter...")
    disableContentFilter()
    dispatchMain()
case .enableDNSProxy:
    print("Enabling DNS proxy...")
    enableDNSProxy()
    dispatchMain()
case .disableDNSProxy:
    print("Disabling DNS proxy...")
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
