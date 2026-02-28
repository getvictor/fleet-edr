import Foundation
import NetworkExtension

// NEFilterDataProvider lifecycle is managed by the system. The NetworkFilter
// subclass is instantiated automatically via the NEProviderClasses key in
// Info.plist. We only need to start the XPC server here so the filter can
// send events to the agent.

XPCServer.shared.start()

dispatchMain()
