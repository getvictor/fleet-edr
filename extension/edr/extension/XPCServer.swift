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
    /// Signalled once the FIRST peer (the agent) connects post-listener-activate.
    /// Used by the issue #11 startup snapshot pass to avoid emitting baseline
    /// exec events into the void during the brief window between extension
    /// restart + agent XPC reconnect. The semaphore is one-shot: callers wait
    /// until either the first connect (or wait-timeout) and then proceed.
    /// Subsequent peer connects/disconnects do not signal again.
    private let firstPeerSemaphore = DispatchSemaphore(value: 0)
    private var firstPeerSignalled = false

    init(serviceName: String) {
        self.serviceName = serviceName
    }

    /// waitForFirstPeer blocks the calling thread until the listener accepts a peer
    /// connection, or `timeout` elapses, whichever comes first. Returns true if a
    /// peer connected in time. Callers MUST NOT invoke this from a thread that is
    /// also responsible for delivering peer events (eg the xpcserver dispatch queue);
    /// the snapshot enumerator runs on a background utility queue specifically to
    /// keep this constraint satisfied.
    func waitForFirstPeer(timeout: DispatchTime) -> Bool {
        guard firstPeerSemaphore.wait(timeout: timeout) == .success else {
            // Timed out without ever observing the first-peer signal. Do NOT
            // re-signal here — a spurious signal would credit a later waiter
            // with a peer connection that never happened, violating the
            // return contract. Snapshot enumerator handles the false return
            // by skipping the pass for this boot.
            return false
        }
        // Re-signal so any subsequent waiter also returns immediately. The
        // semaphore is otherwise consumed by the first wait, leaving later
        // callers to block forever if the connect never happens a second time.
        firstPeerSemaphore.signal()
        return true
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
    ///   - "hello" : the handshake the agent uses to trigger the Mach port bind.
    ///   - "application_control.update" : a typed snapshot push from the
    ///     server's fan-out. The "data" key holds raw JSON bytes that
    ///     ApplicationControlStore decodes + persists.
    ///
    /// Unknown types are logged and ignored — future protocol evolutions should be
    /// additive, and a forward-compat agent must still work against this server.
    private func handlePeerMessage(_ event: xpc_object_t) {
        guard let typeCStr = xpc_dictionary_get_string(event, "type") else {
            return
        }
        let type = String(cString: typeCStr)
        // "hello" is a no-op: the mere receipt of the message triggered the lazy Mach
        // port connection; there's nothing to do server-side.
        if type == "hello" {
            return
        }
        if type == "application_control.update" {
            var dataLen: Int = 0
            guard let rawPtr = xpc_dictionary_get_data(event, "data", &dataLen), dataLen > 0 else {
                logger.error("application_control.update missing 'data'")
                return
            }
            let data = Data(bytes: rawPtr, count: dataLen)
            ApplicationControlStore.shared.apply(rawJSON: data)
            return
        }
        // type is peer-supplied; redact in the unified log so a compromised peer
        // cannot inject arbitrary strings into log readers.
        logger.info("unknown XPC message type: \(type, privacy: .private)")
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
            // Unblock the issue #11 snapshot enumerator on the FIRST peer. Subsequent
            // connects after a disconnect/reconnect cycle don't re-signal — the
            // snapshot pass is a one-shot startup operation.
            if !firstPeerSignalled {
                firstPeerSignalled = true
                firstPeerSemaphore.signal()
            }

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
