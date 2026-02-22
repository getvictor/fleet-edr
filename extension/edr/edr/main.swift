import Foundation
import os.log
import SystemExtensions

private let logger = Logger(subsystem: "com.fleet.edr", category: "main")
private let extensionID = "com.fleet.edr.extension"

final class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    private let action: String

    init(action: String) {
        self.action = action
    }

    func run() {
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
            logger.info("\(self.action) completed")
            exit(EXIT_SUCCESS)
        case .willCompleteAfterReboot:
            logger.info("\(self.action) will complete after reboot")
            exit(EXIT_SUCCESS)
        @unknown default:
            logger.error("Unknown result: \(result.rawValue)")
            exit(EXIT_FAILURE)
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        logger.error("\(self.action) failed: \(error.localizedDescription)")
        exit(EXIT_FAILURE)
    }
}

let action = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "activate"
let manager = ExtensionManager(action: action)
manager.run()
dispatchMain()
