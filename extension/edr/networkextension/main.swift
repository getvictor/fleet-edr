import Foundation
import NetworkExtension

let server = XPCServer(serviceName: "com.fleet.edr.networkextension")
server.start()

let filter = NetworkFilter()
filter.onEvent = { data in server.send(data: data) }

dispatchMain()
