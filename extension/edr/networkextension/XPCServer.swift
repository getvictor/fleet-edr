import Foundation
import os.log

/// The network extension's XPC server: a shared XPCEventServer (see shared/XPCEventServer.swift) bound to the network
/// extension's app-group Mach service. It has no inbound control messages (unlike the security extension's
/// application_control.update), so onApplicationControl is nil. NetworkFilter + DNSProxyProvider broadcast events via
/// XPCServer.shared.send; main.swift starts the listener via XPCServer.shared.start.
///
/// The service name MUST be the app-group NEMachServiceName: that is the only Mach service launchd registers for a
/// NetworkExtension sysext. A team-prefixed name (the kind the security extension vends via NSEndpointSecurityMachServiceName)
/// is never bound for an NE, so a listener on it gets no bootstrap registration and the agent's connect fails with
/// "xpc_bridge_connect failed". The agent reaches this app-group name fine (verified on edr-qa); #300 switched this to a
/// team-prefixed name on a false premise and silently broke NE event delivery.
enum XPCServer {
    static let shared = XPCEventServer(
        serviceName: "group.com.fleetdm.edr.networkextension",
        logger: Logger(subsystem: "com.fleetdm.edr.networkextension", category: "XPCServer")
    )
}
