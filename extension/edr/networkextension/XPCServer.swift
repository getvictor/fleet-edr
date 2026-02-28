import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleet.edr.networkextension", category: "XPCServer")

/// XPCServer vends a Mach service that the Go agent connects to.
/// Network events are broadcast to all connected peers as XPC dictionaries
/// with a "data" key containing raw JSON bytes.
final class XPCServer {
    private let serviceName: String
    private var listener: xpc_connection_t?
    private var peers: Set<XPCPeer> = []
    private let queue = DispatchQueue(label: "com.fleet.edr.networkextension.xpcserver")

    init(serviceName: String) {
        self.serviceName = serviceName
    }

    func start() {
        let conn = xpc_connection_create_mach_service(
            serviceName, queue,
            UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
        )

        xpc_connection_set_event_handler(conn) { [weak self] event in
            self?.handleListenerEvent(event)
        }

        xpc_connection_activate(conn)
        listener = conn
        logger.info("XPC listener started on \(self.serviceName)")
    }

    func send(data: Data) {
        queue.async { [weak self] in
            guard let self else { return }
            let msg = xpc_dictionary_create_empty()
            data.withUnsafeBytes { buf in
                guard let baseAddress = buf.baseAddress else { return }
                xpc_dictionary_set_data(msg, "data", baseAddress, buf.count)
            }
            for peer in self.peers {
                xpc_connection_send_message(peer.connection, msg)
            }
        }
    }

    private func handleListenerEvent(_ event: xpc_object_t) {
        let type = xpc_get_type(event)

        if type == XPC_TYPE_CONNECTION {
            let peer = XPCPeer(connection: event)
            peers.insert(peer)
            logger.info("Peer connected (total: \(self.peers.count))")

            xpc_connection_set_event_handler(event) { [weak self] peerEvent in
                let peerType = xpc_get_type(peerEvent)
                if peerType == XPC_TYPE_ERROR {
                    self?.queue.async {
                        self?.peers.remove(peer)
                        logger.info("Peer disconnected (total: \(self?.peers.count ?? 0))")
                    }
                }
            }

            xpc_connection_activate(event)
        } else if type == XPC_TYPE_ERROR {
            logger.error("Listener error")
        }
    }
}

/// Wraps an xpc_connection_t so it can be stored in a Set.
private final class XPCPeer: Hashable {
    let connection: xpc_connection_t

    init(connection: xpc_connection_t) {
        self.connection = connection
    }

    static func == (lhs: XPCPeer, rhs: XPCPeer) -> Bool {
        lhs.connection === rhs.connection
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(connection as AnyObject))
    }
}
