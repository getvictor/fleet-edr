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

/// Holds the provider-liveness broadcaster. A separate type from XPCServer on purpose: the two reference each other
/// (the server re-publishes on peer hello, the reporter sends through the server), and Swift rejects that as a circular
/// reference when both are statics of the same type. Split apart, each side resolves lazily at first use.
///
/// Broadcasts which providers are actually running so agent health keys on provider liveness rather than on the XPC
/// listener merely being up (issue #649). The listener starts in main.swift BEFORE the providers do, so "the agent
/// connected" has never been evidence that anything is capturing.
enum ProviderStatus {
    static let shared = ProviderStatusReporter(
        broadcast: { XPCServer.shared.send(data: $0) },
        serialize: { NetworkEventSerializer().serialize(eventType: ProviderStatusReporter.eventType, payload: $0) }
    )
}
