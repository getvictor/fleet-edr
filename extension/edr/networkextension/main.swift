import Foundation
import NetworkExtension

// Start the XPC server so the filter can send events to the agent.
XPCServer.shared.start()

// Register with the NetworkExtension framework as a system extension provider.
// This tells nesessionmanager that this process is the provider for the
// extension points declared in Info.plist (NEProviderClasses).
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
