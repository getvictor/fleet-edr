import Foundation
import EndpointSecurity

// Application Control phase 1 removes the legacy blocklist; AUTH_EXEC currently
// allows every exec. The phase-4 decision engine will reintroduce a persisted
// snapshot load here.

let server = XPCServer(serviceName: "FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc")
server.start()

let subscriber = ESFSubscriber()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

dispatchMain()
