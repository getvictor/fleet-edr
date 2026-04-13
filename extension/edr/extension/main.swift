import Foundation
import EndpointSecurity

let server = XPCServer(serviceName: "8VBZ3948LU.com.fleetdm.edr.securityextension.xpc")
server.start()

let subscriber = ESFSubscriber()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

dispatchMain()
