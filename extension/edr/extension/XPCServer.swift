import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "XPCServer")

/// Code signing requirement that peers must satisfy to connect to the XPC service.
/// Accepts any binary signed with the Fleet Device Management team ID (FDG8Q7N4CC).
private let peerCodeSigningRequirement = "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""

/// Cap on the no-peer buffer. ~10k events at ~500B each = ~5MB of memory in the worst case,
/// which is fine for an extension that already keeps ESF deadlines alive on a few-second
/// latency budget. Once full, oldest entries are dropped (lossy FIFO) so a stuck agent
/// can never OOM the extension.
private let pendingSendCap = 10_000

/// Milliseconds to wait after a peer connect before flushing the pending-send buffer to
/// that peer. Long enough to let a phantom peer (observed ~10ms lifetime in edr-dev QA)
/// disconnect itself; short enough that real peers don't perceive a startup-events stall.
private let pendingFlushDelayMs = 250

/// XPCServer vends a Mach service that the Go agent connects to.
/// Serialized ESF events are broadcast to all connected peers as
/// XPC dictionaries with a "data" key containing raw JSON bytes.
///
/// Startup race the buffer handles (issue #11 + #173 review): on extension restart a
/// phantom XPC peer can connect-and-immediately-disconnect within a few ms — observed
/// empirically as "Peer connected (total: 1)" followed by "Peer disconnected (total: 0)"
/// 10ms later, with the real agent peer arriving a second or two afterwards. Without the
/// buffer, every event the extension sends in that window (snapshot pass, plus the first
/// few live execs) goes into an empty peer set and is silently lost. The buffer captures
/// those sends so the next connecting peer drains them on accept.
final class XPCServer {
    private let serviceName: String
    private var listener: xpc_connection_t?
    private var peers: Set<XPCPeer> = []
    private let queue = DispatchQueue(label: "com.fleetdm.edr.xpcserver")
    /// FIFO buffer of event payloads enqueued while no peer was connected. Drained to the
    /// next peer that connects (in order, oldest-first). All access on `queue`.
    private var pendingSends: [Data] = []

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

    /// send enqueues an event payload for delivery to every connected peer. When no peer
    /// is connected the event is appended to pendingSends and flushed to the next peer
    /// that connects. Drops oldest entries when the buffer fills (lossy FIFO) so a stuck
    /// or never-connecting agent can never OOM the extension.
    func send(data: Data) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.peers.isEmpty {
                self.appendPending(data)
                return
            }
            self.broadcastLocked(data)
        }
    }

    // MARK: - Private — all callers run on `queue`

    private func appendPending(_ data: Data) {
        pendingSends.append(data)
        if pendingSends.count > pendingSendCap {
            let drop = pendingSends.count - pendingSendCap
            pendingSends.removeFirst(drop)
            logger.warning("XPC peer absent; dropped \(drop, privacy: .public) oldest pending events (cap \(pendingSendCap, privacy: .public))")
        }
    }

    private func broadcastLocked(_ data: Data) {
        let msg = xpc_dictionary_create_empty()
        data.withUnsafeBytes { buf in
            guard let baseAddress = buf.baseAddress else { return }
            xpc_dictionary_set_data(msg, "data", baseAddress, buf.count)
        }
        for peer in peers {
            xpc_connection_send_message(peer.connection, msg)
        }
    }

    /// flushPendingTo sends every buffered event to the freshly-connected peer in order,
    /// then clears the buffer. Sending to one peer rather than broadcasting to all peers
    /// reflects the design contract: a queued event is the same event the broadcast would
    /// have delivered, and at the moment it was queued there were no peers — the newly
    /// arriving peer is the rightful recipient. If a SECOND peer connects later, that's
    /// a separate session and doesn't get the historical buffer.
    private func flushPendingTo(_ peer: XPCPeer) {
        guard !pendingSends.isEmpty else { return }
        let count = pendingSends.count
        for data in pendingSends {
            let msg = xpc_dictionary_create_empty()
            data.withUnsafeBytes { buf in
                guard let baseAddress = buf.baseAddress else { return }
                xpc_dictionary_set_data(msg, "data", baseAddress, buf.count)
            }
            xpc_connection_send_message(peer.connection, msg)
        }
        pendingSends.removeAll(keepingCapacity: false)
        logger.info("XPC flushed \(count, privacy: .public) buffered events to newly-connected peer")
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
            // Flush buffered events ONLY to peers that survive the hello round-trip. The
            // phantom-peer race (issue #173 QA) is observed as a connect → disconnect
            // pair within ~10ms with no inbound dictionary between them; sending to a
            // phantom drops the events into the void. Gate the flush on the agent's
            // first inbound "hello" message: a peer that produces a hello has a working
            // bidirectional channel and is the rightful recipient of the buffer.
            //
            // We approximate "got hello" by deferring the flush slightly. If the peer is
            // truly alive it stays in `peers`; if it was phantom it has already been
            // removed by the time the deferred block runs. 250ms comfortably exceeds the
            // 10ms phantom-peer lifetime observed in QA on edr-dev.
            queue.asyncAfter(deadline: .now() + .milliseconds(pendingFlushDelayMs)) { [weak self] in
                guard let self else { return }
                guard self.peers.contains(peer) else {
                    logger.info("Peer was phantom (disconnected before flush deadline); buffer retained for next real peer")
                    return
                }
                self.flushPendingTo(peer)
            }
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
