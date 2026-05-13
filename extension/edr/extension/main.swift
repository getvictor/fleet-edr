import Foundation
import EndpointSecurity

// Load the persisted application control snapshot BEFORE ESF starts subscribing.
// Startup order matters here — if we subscribed first, a racing exec of a blocked
// hash between subscribe and loadFromDisk would not yet see the snapshot. The
// Phase 3 decision engine plugs into ESFSubscriber's AUTH_EXEC handler; this
// step (Phase 2) wires the snapshot lifecycle so it's ready when Phase 3 lands.
ApplicationControlStore.shared.loadFromDisk()

let server = XPCServer(serviceName: "FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc")
server.start()

let subscriber = ESFSubscriber()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

dispatchMain()
