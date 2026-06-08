import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "XPCServer")

/// Code signing requirement that peers must satisfy to connect to the XPC service.
/// Accepts any binary signed with the Fleet Device Management team ID (FDG8Q7N4CC).
private let peerCodeSigningRequirement = "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""

/// XPCServer vends a Mach service that the Go agent connects to.
/// Network events are broadcast to all connected peers as XPC dictionaries
/// with a "data" key containing raw JSON bytes.
final class XPCServer {
    // Team-prefixed Mach service (globally resolvable), NOT the app-group-scoped name: the Go agent does not hold the
    // app-group entitlement, so a group.* name is unreachable from it. The app-group name stays as NEMachServiceName in
    // Info.plist for the NetworkExtension framework, which Apple requires to be app-group-scoped.
    static let shared = XPCServer(serviceName: "FDG8Q7N4CC.com.fleetdm.edr.networkextension.xpc")

    private let serviceName: String
    private var listener: xpc_connection_t?
    private var peers: Set<XPCPeer> = []
    private let queue = DispatchQueue(label: "com.fleetdm.edr.networkextension.xpcserver")

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
                    self?.handlePeerMessage(peerEvent, peer: peer)
                }
            }

            xpc_connection_activate(event)
        } else if type == XPC_TYPE_ERROR {
            logger.error("Listener error")
        }
    }

    /// handlePeerMessage replies to the agent's "hello" with "hello-ack" to complete the connect handshake. The agent's
    /// xpc_bridge_connect sends "hello" and tears the connection down if no "hello-ack" arrives within 5s
    /// (agent/xpcbridge/xpc_bridge.c, issue #178); without this reply the agent's network-extension receiver timed out
    /// every reconnect cycle and the extension delivered no network/DNS events. The network extension has no inbound
    /// control messages (unlike the security extension's application_control.update), so any other type is ignored.
    private func handlePeerMessage(_ event: xpc_object_t, peer: XPCPeer) {
        let typeStr = xpc_dictionary_get_string(event, "type").map { String(cString: $0) }
        guard networkXPCShouldAck(type: typeStr) else {
            // type is peer-supplied; redact in the unified log so a compromised peer cannot inject arbitrary strings.
            logger.info("unknown XPC message type: \(typeStr ?? "(none)", privacy: .private)")
            return
        }
        let ack = xpc_dictionary_create_empty()
        xpc_dictionary_set_string(ack, "type", NetworkXPCMessageType.helloAck)
        xpc_connection_send_message(peer.connection, ack)
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
