import Foundation
import NetworkExtension

// Start the XPC server so the filter can send events to the agent. The peer hook re-broadcasts provider liveness on
// every agent hello: this listener comes up BEFORE the providers below, so an agent connecting here has no evidence
// that anything is actually capturing, which is the bug behind issue #649.
XPCServer.shared.start(onPeerConnected: { ProviderStatus.shared.publish() })

// Register with the NetworkExtension framework as a system extension provider.
// This tells nesessionmanager that this process is the provider for the
// extension points declared in Info.plist (NEProviderClasses).
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
