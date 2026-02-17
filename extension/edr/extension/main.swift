import Foundation
import EndpointSecurity

let server = XPCServer(serviceName: "com.fleet.edr.extension")
server.start()

let subscriber = ESFSubscriber()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

dispatchMain()
