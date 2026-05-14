import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr", category: "NotificationListener")

/// NotificationListener is the host-app's inbound XPC surface. It
/// vends the Mach service the extension's NotificationClient
/// connects to, validates the peer is signed by Fleet, decodes the
/// block-notification payload, and dispatches each accepted message
/// to the BlockAlert presenter.
///
/// Mirrors the extension's existing XPCServer shape on purpose: same
/// listener model, same per-peer event handler, same code-signing
/// requirement string. Keeping the two surfaces structurally similar
/// means a fix in one (a CodeRabbit-flagged race, a missing nil
/// check) is easy to port to the other.
final class NotificationListener {
    private let serviceName: String
    private let presenter: BlockAlertPresenter
    private let queue = DispatchQueue(label: "com.fleetdm.edr.notification-listener")
    private var listener: xpc_connection_t?
    private var peers: Set<NotificationPeer> = []

    init(serviceName: String = blockNotificationServiceName, presenter: BlockAlertPresenter) {
        self.serviceName = serviceName
        self.presenter = presenter
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
        logger.info("notification listener started on \(self.serviceName, privacy: .public)")
    }

    private func handleListenerEvent(_ event: xpc_object_t) {
        let type = xpc_get_type(event)
        if type == XPC_TYPE_CONNECTION {
            let result = xpc_connection_set_peer_code_signing_requirement(event, blockNotificationPeerRequirement)
            if result != 0 {
                logger.error("set peer code signing on notification listener: \(result, privacy: .public)")
                xpc_connection_cancel(event)
                return
            }
            let peer = NotificationPeer(connection: event)
            peers.insert(peer)
            logger.info("notification peer connected (total: \(self.peers.count, privacy: .public))")
            xpc_connection_set_event_handler(event) { [weak self] peerEvent in
                let peerType = xpc_get_type(peerEvent)
                if peerType == XPC_TYPE_ERROR {
                    self?.queue.async {
                        self?.peers.remove(peer)
                        logger.info("notification peer disconnected (total: \(self?.peers.count ?? 0, privacy: .public))")
                    }
                    return
                }
                if peerType == XPC_TYPE_DICTIONARY {
                    self?.handlePeerMessage(peerEvent)
                }
            }
            xpc_connection_activate(event)
        } else if type == XPC_TYPE_ERROR {
            logger.error("notification listener error")
        }
    }

    private func handlePeerMessage(_ event: xpc_object_t) {
        guard let typeCStr = xpc_dictionary_get_string(event, "type") else {
            return
        }
        let kind = String(cString: typeCStr)
        guard kind == blockNotificationMessageType else {
            // type is peer-supplied; redact in the unified log so a
            // compromised peer cannot inject arbitrary strings.
            logger.info("ignored XPC message of unknown type: \(kind, privacy: .private)")
            return
        }
        var dataLen = 0
        guard let rawPtr = xpc_dictionary_get_data(event, "data", &dataLen), dataLen > 0 else {
            logger.error("block notification missing 'data'")
            return
        }
        let data = Data(bytes: rawPtr, count: dataLen)
        let decoder = JSONDecoder()
        let payload: BlockNotificationPayload
        do {
            payload = try decoder.decode(BlockNotificationPayload.self, from: data)
        } catch {
            logger.error("decode block notification: \(error.localizedDescription, privacy: .public)")
            return
        }
        presenter.present(payload)
    }
}

/// NotificationPeer wraps an xpc_connection_t so we can store it in
/// a Set. Same shape as the agent ↔ extension XPCServer's XPCPeer.
private final class NotificationPeer: Hashable {
    let connection: xpc_connection_t
    init(connection: xpc_connection_t) {
        self.connection = connection
    }
    static func == (lhs: NotificationPeer, rhs: NotificationPeer) -> Bool {
        lhs.connection === rhs.connection
    }
    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(connection as AnyObject))
    }
}
