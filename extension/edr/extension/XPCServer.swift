import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "XPCServer")

/// Code signing requirement that peers must satisfy to connect to the XPC service.
/// Production: only binaries signed with the Fleet Device Management team ID
/// (FDG8Q7N4CC) pass. Debug builds additionally accept the pinned cdhash of the
/// locally-built ad-hoc agent so dev iteration on SIP-off VMs works -- `go build`
/// produces an ad-hoc signature with no team ID, so the strict production
/// requirement would lock dev iteration out (observed on edr-dev as
/// "Received message forbidden due to code signing requirement" rejecting the
/// agent's hello message).
///
/// The cdhash clause pins to ONE specific hash, not "any ad-hoc binary." A
/// different ad-hoc-signed process cannot impersonate the agent. `#if DEBUG`
/// excludes the entire ad-hoc branch from release builds so production binaries
/// are team-id-only even if this constant is left in source.
#if DEBUG
private let peerCodeSigningRequirement = """
    (anchor apple generic and certificate leaf[subject.OU] = "FDG8Q7N4CC") or \
    cdhash H"\(adHocPeerCDHash)"
    """

/// cdhash of the locally-built ad-hoc agent binary. Update via `task build:agent`
/// followed by `codesign -d -r - agent/tmp/fleet-edr-agent` to read the new hash.
/// Go's deterministic builds keep this stable across rebuilds of identical
/// source, so the update cadence matches Go-side code changes, not every build.
private let adHocPeerCDHash = "2a10e75d40cc0fe1a7d93c6ec7d91799a8eff189"
#else
private let peerCodeSigningRequirement = "anchor apple generic and certificate leaf[subject.OU] = \"FDG8Q7N4CC\""
#endif

/// Cap on the no-peer buffer. ~10k events at ~500B each = ~5MB of memory in the worst case,
/// which is fine for an extension that already keeps ESF deadlines alive on a few-second
/// latency budget. Once full, oldest entries are dropped (lossy FIFO) so a stuck agent
/// can never OOM the extension.
private let pendingSendCap = 10_000

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
    ///               We reply with "hello-ack" and flush any pending events to this peer
    ///               — receiving the hello is positive proof the channel is alive in both
    ///               directions, which the agent uses to detect stale Mach port bindings
    ///               post-extension-respawn (issue #178).
    ///   - "application_control.update" : a typed snapshot push from the
    ///     server's fan-out. The "data" key holds raw JSON bytes that
    ///     ApplicationControlStore decodes + persists.
    ///
    /// Unknown types are logged and ignored — future protocol evolutions should be
    /// additive, and a forward-compat agent must still work against this server.
    private func handlePeerMessage(_ event: xpc_object_t, peer: XPCPeer) {
        guard let typeCStr = xpc_dictionary_get_string(event, "type") else {
            return
        }
        let type = String(cString: typeCStr)
        if type == "hello" {
            let ack = xpc_dictionary_create_empty()
            xpc_dictionary_set_string(ack, "type", "hello-ack")
            xpc_connection_send_message(peer.connection, ack)
            // Receipt of hello is positive proof this peer is the real agent (not a
            // phantom). Flush any events buffered while no peer was connected so the
            // agent picks them up immediately rather than after the first natural exec.
            flushPendingTo(peer)
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
                    self?.handlePeerMessage(peerEvent, peer: peer)
                }
            }

            xpc_connection_activate(event)
            // Buffer flush is gated on receiving the peer's "hello" message rather than
            // a time-based fallback (issue #178). A real agent peer sends hello to
            // trigger the lazy Mach port bind; a phantom peer (observed in QA: connect
            // → disconnect within ~10ms with no inbound traffic) never sends hello and
            // therefore never gets the buffer. handlePeerMessage handles the flush.
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
