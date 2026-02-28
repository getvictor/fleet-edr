import Foundation
import NetworkExtension
import os.log
import SystemExtensions

private let logger = Logger(subsystem: "com.fleet.edr", category: "main")
private let esfExtensionID = "com.fleet.edr.extension"
private let netExtensionID = "com.fleet.edr.networkextension"

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
            let request: OSSystemExtensionRequest
            switch action {
            case "deactivate":
                request = OSSystemExtensionRequest.deactivationRequest(
                    forExtensionWithIdentifier: extensionID, queue: .main)
            default:
                request = OSSystemExtensionRequest.activationRequest(
                    forExtensionWithIdentifier: extensionID, queue: .main)
            }
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
            logger.info("\(self.action) request submitted for \(extensionID)")
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
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

    private func enableContentFilter() {
        NEFilterManager.shared().loadFromPreferences { error in
            if let error {
                logger.error("Failed to load filter preferences: \(error.localizedDescription)")
                exit(EXIT_FAILURE)
            }

            let filterConfig = NEFilterProviderConfiguration()
            filterConfig.filterSockets = true
            filterConfig.filterPackets = false

            NEFilterManager.shared().providerConfiguration = filterConfig
            NEFilterManager.shared().localizedDescription = "Fleet EDR Network Monitor"
            NEFilterManager.shared().isEnabled = true

            NEFilterManager.shared().saveToPreferences { error in
                if let error {
                    logger.error("Failed to save filter preferences: \(error.localizedDescription)")
                    exit(EXIT_FAILURE)
                }
                logger.info("Content filter enabled")
                exit(EXIT_SUCCESS)
            }
        }
    }
}

let action = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "activate"
let manager = ExtensionManager(action: action)
manager.run()
dispatchMain()
