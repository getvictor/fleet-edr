import AppKit
import Foundation
import NetworkExtension
import os.log
import SystemExtensions

private let logger = Logger(subsystem: "com.fleetdm.edr", category: "main")
private let esfExtensionID = "com.fleetdm.edr.securityextension"
private let netExtensionID = "com.fleetdm.edr.networkextension"

final class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    private let action: String
    private var pendingCount = 0
    private var hadFailure = false

    init(action: String) {
        self.action = action
    }

    func run() {
        let extensionIDs = [esfExtensionID, netExtensionID]
        pendingCount = extensionIDs.count

        for extensionID in extensionIDs {
            let request: OSSystemExtensionRequest = if action == "deactivate" {
                OSSystemExtensionRequest.deactivationRequest(
                    forExtensionWithIdentifier: extensionID, queue: .main)
            } else {
                OSSystemExtensionRequest.activationRequest(
                    forExtensionWithIdentifier: extensionID, queue: .main)
            }
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
            logger.info("\(self.action) request submitted for \(extensionID)")
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
        logger.info("Waiting for user approval in System Settings")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            logger.info("\(self.action) completed for \(request.identifier)")
        case .willCompleteAfterReboot:
            logger.info("\(self.action) will complete after reboot for \(request.identifier)")
        @unknown default:
            logger.error("Unknown result for \(request.identifier): \(result.rawValue)")
            hadFailure = true
        }

        pendingCount -= 1
        if pendingCount <= 0 {
            if hadFailure {
                exit(EXIT_FAILURE)
            } else if action != "deactivate" {
                enableContentFilter()
            } else {
                exit(EXIT_SUCCESS)
            }
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        logger.error("\(self.action) failed for \(request.identifier): \(error.localizedDescription)")
        hadFailure = true
        pendingCount -= 1
        if pendingCount <= 0 {
            exit(EXIT_FAILURE)
        }
    }
}

private func enableContentFilter() {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error {
            print("ERROR: Failed to load filter preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
        }
        print("Loaded filter preferences, isEnabled=\(NEFilterManager.shared().isEnabled)")

        let filterConfig = NEFilterProviderConfiguration()
        filterConfig.filterSockets = true
        filterConfig.filterPackets = false

        NEFilterManager.shared().providerConfiguration = filterConfig
        NEFilterManager.shared().localizedDescription = "Fleet EDR Network Monitor"
        NEFilterManager.shared().isEnabled = true

        print("Saving filter preferences...")
        NEFilterManager.shared().saveToPreferences { error in
            if let error {
                print("ERROR: Failed to save filter preferences: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            print("Content filter enabled successfully")
            exit(EXIT_SUCCESS)
        }
    }
}

private func enableDNSProxy() {
    NEDNSProxyManager.shared().loadFromPreferences { error in
        if let error {
            print("ERROR: Failed to load DNS proxy preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
        }

        let proxyConfig = NEDNSProxyProviderProtocol()
        proxyConfig.providerBundleIdentifier = netExtensionID

        NEDNSProxyManager.shared().providerProtocol = proxyConfig
        NEDNSProxyManager.shared().localizedDescription = "Fleet EDR DNS Monitor"
        NEDNSProxyManager.shared().isEnabled = true

        NEDNSProxyManager.shared().saveToPreferences { error in
            if let error {
                print("ERROR: Failed to save DNS proxy preferences: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            print("DNS proxy enabled successfully")
            exit(EXIT_SUCCESS)
        }
    }
}

private func disableContentFilter() {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error {
            print("ERROR: Failed to load filter preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
        }
        NEFilterManager.shared().isEnabled = false
        NEFilterManager.shared().saveToPreferences { error in
            if let error {
                print("ERROR: Failed to disable filter: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            print("Content filter disabled")
            exit(EXIT_SUCCESS)
        }
    }
}

private func disableDNSProxy() {
    NEDNSProxyManager.shared().loadFromPreferences { error in
        if let error {
            print("ERROR: Failed to load DNS proxy preferences: \(error.localizedDescription)")
            exit(EXIT_FAILURE)
        }
        NEDNSProxyManager.shared().isEnabled = false
        NEDNSProxyManager.shared().saveToPreferences { error in
            if let error {
                print("ERROR: Failed to disable DNS proxy: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }
            print("DNS proxy disabled")
            exit(EXIT_SUCCESS)
        }
    }
}

/// runNotifyMode keeps the host app alive as a long-running
/// accessory NSApplication, vending the block-notification XPC
/// service and presenting NSAlert modals on every accepted
/// AUTH_EXEC-denied notification. Distinct from the other CLI
/// modes (one-shot extension activation, filter toggles) which run
/// dispatchMain and exit on completion — the notify surface has no
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
    // optimised builds — caught by Gemini and Copilot on PR #157.
    withExtendedLifetime(listener) {
        app.run()
    }
}

let action = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "activate"

switch action {
case "enable-filter":
    print("Enabling content filter...")
    enableContentFilter()
    dispatchMain()
case "disable-filter":
    print("Disabling content filter...")
    disableContentFilter()
    dispatchMain()
case "enable-dns-proxy":
    print("Enabling DNS proxy...")
    enableDNSProxy()
    dispatchMain()
case "disable-dns-proxy":
    print("Disabling DNS proxy...")
    disableDNSProxy()
    dispatchMain()
case "notify":
    print("Starting Fleet EDR notification surface...")
    runNotifyMode()
default:
    let manager = ExtensionManager(action: action)
    manager.run()
    dispatchMain()
}
