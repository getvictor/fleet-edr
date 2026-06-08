import Foundation
import os.log

/// The network extension's XPC server: a shared XPCEventServer (see shared/XPCEventServer.swift) bound to the network
/// extension's team-prefixed Mach service. It has no inbound control messages (unlike the security extension's
/// application_control.update), so onApplicationControl is nil. NetworkFilter + DNSProxyProvider broadcast events via
/// XPCServer.shared.send; main.swift starts the listener via XPCServer.shared.start.
///
/// Team-prefixed Mach service (globally resolvable), NOT the app-group-scoped name: the Go agent does not hold the
/// app-group entitlement, so a group.* name is unreachable from it. The app-group name stays as NEMachServiceName in
/// Info.plist for the NetworkExtension framework, which Apple requires to be app-group-scoped.
enum XPCServer {
    static let shared = XPCEventServer(
        serviceName: "FDG8Q7N4CC.com.fleetdm.edr.networkextension.xpc",
        logger: Logger(subsystem: "com.fleetdm.edr.networkextension", category: "XPCServer")
    )
}
