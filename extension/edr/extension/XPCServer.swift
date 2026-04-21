import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "XPCServer")

/// Code signing requirement that peers must satisfy to connect to the XPC service.
/// Accepts any binary signed with the Fleet Device Management team ID (FDG8Q7N4CC).
private let peerCodeSigningRequirement = "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""

/// XPCServer vends a Mach service that the Go agent connects to.
/// Serialized ESF events are broadcast to all connected peers as
/// XPC dictionaries with a "data" key containing raw JSON bytes.
final class XPCServer {
    private let serviceName: String
    private var listener: xpc_connection_t?
    private var peers: Set<XPCPeer> = []
    private let queue = DispatchQueue(label: "com.fleetdm.edr.xpcserver")

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

    /// handlePeerMessage dispatches an inbound XPC dictionary from a connected peer (the
    /// agent). The protocol is tiny: a "type" string tells us what kind of message it is.
    ///
    ///   - "hello"         : the handshake the agent uses to trigger the Mach port bind.
    ///   - "policy.update" : Phase 2 blocklist push. The "data" key holds raw JSON bytes
    ///                       that PolicyStore decodes + persists.
    ///
    /// Unknown types are logged and ignored — future protocol evolutions should be
    /// additive, and a forward-compat agent must still work against this server.
    private func handlePeerMessage(_ event: xpc_object_t) {
        guard let typeCStr = xpc_dictionary_get_string(event, "type") else {
            return
        }
        let type = String(cString: typeCStr)
        switch type {
        case "hello":
            // No-op. The mere receipt of this message triggered the lazy Mach port
            // connection; there's nothing to do server-side.
            break
        case "policy.update":
            var dataLen: Int = 0
            guard let rawPtr = xpc_dictionary_get_data(event, "data", &dataLen), dataLen > 0 else {
                logger.error("policy.update missing 'data'")
                return
            }
            let data = Data(bytes: rawPtr, count: dataLen)
            PolicyStore.shared.apply(rawJSON: data)
        default:
            logger.info("unknown XPC message type: \(type, privacy: .public)")
        }
    }

    private func handleListenerEvent(_ event: xpc_object_t) {
        let type = xpc_get_type(event)

        if type == XPC_TYPE_CONNECTION {
            // Validate peer code signing before accepting the connection.
            // The agent binary must be signed with --options runtime for this to work.
            let result = xpc_connection_set_peer_code_signing_requirement(event, peerCodeSigningRequirement)
            if result != 0 {
                logger.error("Failed to set peer code signing requirement: \(result)")
                xpc_connection_cancel(event)
                return
            }

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
                    return
                }
                if peerType == XPC_TYPE_DICTIONARY {
                    self?.handlePeerMessage(peerEvent)
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
