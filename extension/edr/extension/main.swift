import Foundation
import EndpointSecurity

// Phase 2: load any persisted blocklist BEFORE ESF starts subscribing. Startup order
// matters here — if we subscribed first, a racing exec of a blocked path between
// subscribe and loadFromDisk would be incorrectly allowed.
PolicyStore.shared.loadFromDisk()

let server = XPCServer(serviceName: "FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc")
server.start()

let subscriber = ESFSubscriber()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

dispatchMain()
