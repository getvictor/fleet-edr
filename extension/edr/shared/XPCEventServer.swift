import Foundation
import os.log

/// PeerCodeSigningRequirement vends the two requirement strings the XPC server pins peers against. Exposed as type-level
/// constants so the unit tests can assert the requirement language on both production and debug paths without spinning
/// up an XPC listener.
///
/// Production: only binaries signed with the Fleet Device Management team ID (FDG8Q7N4CC, chained to the Apple anchor)
/// pass. Debug builds additionally accept the locally-built ad-hoc agent by its code-signing IDENTIFIER so dev iteration
/// on SIP-disabled VMs works: `go build` produces an ad-hoc signature with no team ID, so the strict production
/// requirement would lock dev iteration out (observed on edr-dev as "Received message forbidden due to code signing
/// requirement" rejecting the agent's hello message). Pinning the identifier rather than a content-derived cdhash is the
/// deferred tightening ADR-0007 anticipated: `task build:agent` re-signs the ad-hoc binary with the fixed identifier
/// `fleet-edr-agent` (the same designated identifier the notarized release carries), so the pin no longer goes stale on
/// every rebuild the way the old committed cdhash did (issue #623). The active `peerCodeSigningRequirement` constant
/// below excludes the ad-hoc branch from release builds so production binaries are team-id-only even if the .debug string
/// is left in source.
enum PeerCodeSigningRequirement {
    /// FDM team ID. Every signed peer that reaches us in production must chain to a leaf cert carrying this OU.
    static let teamID = "FDG8Q7N4CC"

    /// Code-signing identifier of the locally-built ad-hoc agent. `task build:agent` re-signs the binary with
    /// `--identifier fleet-edr-agent` so this value is stable across every rebuild (unlike the content-derived cdhash it
    /// replaced), and it matches the designated identifier the notarized release carries, so no dev re-pinning is needed.
    static let agentIdentifierDebug = "fleet-edr-agent"

    /// Production requirement string: Apple anchor + FDM team ID, nothing else. Used by release-configured extensions.
    static let production = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""

    /// Debug requirement string: production + the ad-hoc agent's fixed identifier. Used by debug-configured extensions
    /// only. On a SIP-disabled dev VM this accepts an ad-hoc binary claiming the agent identifier; that is the accepted
    /// dev-side trade the .debug branch makes, and it never reaches release builds (see peerCodeSigningRequirement).
    static let debug = """
        (anchor apple generic and certificate leaf[subject.OU] = "\(teamID)") or \
        identifier "\(agentIdentifierDebug)"
        """
}

/// The active requirement string the listener applies at peer-accept time. Picks between .production and .debug via
/// `#if DEBUG` so a release extension never accepts the ad-hoc cdhash even if the .debug constant is left in source.
private let peerCodeSigningRequirement: String = {
    #if DEBUG
    return PeerCodeSigningRequirement.debug
    #else
    return PeerCodeSigningRequirement.production
    #endif
}()

/// XPC message-type strings the inbound dispatcher recognises, plus the outbound hello-ack type. Centralised here so a
/// future protocol evolution (adding a new inbound type) touches one place + one switch arm in dispatchInbound.
enum XPCMessageType {
    static let hello = "hello"
    static let helloAck = "hello-ack"
    static let applicationControlUpdate = "application_control.update"
}

/// Cap on the no-peer buffer. ~10k events at ~500B each = ~5MB of memory in the worst case, which is fine for an
/// extension that already keeps ESF deadlines alive on a few-second latency budget. Once full, oldest entries are
/// dropped (lossy FIFO) so a stuck agent can never OOM the extension. File-private because only XPCEventServer + the
/// adjacent log line need it; PendingBuffer takes its cap as an init parameter so it's testable without referencing
/// this constant.
private let pendingSendCap = 10_000

/// Max events flushPendingTo sends per `queue` iteration before yielding the serial queue and re-dispatching the
/// remainder. The pending buffer can hold up to pendingSendCap events (accumulated while the agent was absent), and a
/// single synchronous drain of that depth would monopolise `queue` for the whole loop, delaying any inbound peer
/// message queued behind it (a second peer's hello, an ERROR disconnect). Each xpc_connection_send_message is a
/// non-blocking enqueue, so one chunk is sub-millisecond; yielding between chunks is what bounds the latency another
/// queue item can see behind a deep flush. File-private alongside pendingSendCap.
private let flushChunkSize = 256

/// PendingBuffer is a bounded FIFO of event payloads the XPC server buffers while no peer is connected. Drained to the
/// next peer that completes the hello handshake. Extracted from XPCEventServer so the cap + drop-oldest semantics +
/// drain behaviour are unit-testable without a real XPC peer.
struct PendingBuffer {
    private(set) var entries: [Data] = []
    let cap: Int

    init(cap: Int) {
        precondition(cap > 0, "PendingBuffer cap must be > 0")
        self.cap = cap
    }

    /// append adds `data` to the buffer. Returns the number of entries dropped from the front to fit under cap (0 when
    /// the buffer had room). Callers log on drop > 0 for operator visibility.
    @discardableResult
    mutating func append(_ data: Data) -> Int {
        entries.append(data)
        let overflow = entries.count - cap
        if overflow > 0 {
            entries.removeFirst(overflow)
            return overflow
        }
        return 0
    }

    /// drain returns the buffered entries in append order and empties the buffer. Called when a peer completes the
    /// hello handshake; the caller forwards each entry to that single peer (NOT a broadcast).
    mutating func drain() -> [Data] {
        let out = entries
        entries.removeAll(keepingCapacity: false)
        return out
    }

    var count: Int { entries.count }
    var isEmpty: Bool { entries.isEmpty }
}

/// XPCInboundDispatch is the verdict the dispatcher returns for one inbound XPC dictionary message. The XPC-layer code
/// in XPCEventServer translates each case into the corresponding xpc_connection_send_message + onApplicationControl
/// call; the verdict itself is pure data so unit tests cover every code path without an XPC framework dependency.
enum XPCInboundDispatch: Equatable {
    /// `type = hello`: send hello-ack to this peer + drain the pending buffer to this peer.
    case helloAck
    /// `type = application_control.update` with non-empty `data`: pass the bytes to the onApplicationControl hook.
    case applyApplicationControl(Data)
    /// `type = application_control.update` with missing or empty `data`: ignore + leave the active policy untouched.
    /// Distinct from .ignore so the operator-visible log line can be specific.
    case rejectMissingData
    /// Unknown type, or no `type` field at all: log + ignore. Connection stays open; forward-compat agents can introduce
    /// new types without breaking older extensions.
    case ignore
}

/// dispatchInbound classifies an inbound `(type, data)` pair into an XPCInboundDispatch. Pure function so every
/// extension-xpc-server scenario (hello, application_control.update with + without data, unknown future type) is
/// covered by the unit-test suite.
func dispatchInbound(type: String?, data: Data?) -> XPCInboundDispatch {
    guard let type else { return .ignore }
    switch type {
    case XPCMessageType.hello:
        return .helloAck
    case XPCMessageType.applicationControlUpdate:
        guard let data, !data.isEmpty else { return .rejectMissingData }
        return .applyApplicationControl(data)
    default:
        return .ignore
    }
}

/// XPCEventServer vends a Mach service that the Go agent connects to. Serialized events are broadcast to all connected
/// peers as XPC dictionaries with a "data" key containing raw JSON bytes.
///
/// Shared by the security extension AND the network extension. Each extension instantiates one with its own service
/// name + logger; the security extension also passes an `onApplicationControl` hook to apply inbound app-control policy,
/// while the network extension passes nil (it has no inbound control messages). Both get the identical hello-ack
/// handshake, pending buffer, and peer code-signing. Single-sourcing the handshake means it can no longer drift between
/// the two extensions (the network extension previously lacked the handshake entirely; see the hello-ack fix).
///
/// Startup race the buffer handles (issue #11 + #173 review): on extension restart a phantom XPC peer can
/// connect-and-immediately-disconnect within a few ms: observed empirically as "Peer connected (total: 1)" followed
/// by "Peer disconnected (total: 0)" 10ms later, with the real agent peer arriving a second or two afterwards. Without
/// the buffer, every event the extension sends in that window (snapshot pass, plus the first few live execs) goes into
/// an empty peer set and is silently lost. The buffer captures those sends so the next connecting peer drains them on
/// hello.
final class XPCEventServer {
    private let serviceName: String
    private let log: Logger
    /// Inbound application-control handler. The security extension wires this to ApplicationControlStore.apply; the
    /// network extension passes nil (no inbound control messages), so an application_control.update it never receives
    /// would be a no-op rather than a crash.
    private let onApplicationControl: ((Data) -> Void)?
    /// Called each time a peer completes the hello handshake. The network extension uses it to re-broadcast current
    /// provider liveness (issue #649): that state is level-triggered, not an event, so an agent that connects after the
    /// providers started must be told the current state rather than waiting for a transition that may never come.
    /// Buffered events cannot carry it reliably either, since a busy host can evict a status message from the bounded
    /// pending buffer before the agent ever connects.
    ///
    /// Supplied to `start` rather than to `init` so the caller can reference something that itself references this
    /// server. As a stored property initialised from a static, that mutual reference is a compile-time circular
    /// reference; assigned here, before the listener is activated, each side resolves lazily at first use. Written once
    /// on the caller's thread before any peer can exist, read thereafter on `queue`.
    private var onPeerConnected: (() -> Void)?
    private var listener: xpc_connection_t?
    private var peers: Set<XPCPeer> = []
    private let queue = DispatchQueue(label: "com.fleetdm.edr.xpceventserver")
    /// FIFO buffer of event payloads enqueued while no peer was connected. Drained to the next peer that completes the
    /// hello handshake (in order, oldest-first). All access on `queue`.
    private var pendingBuffer = PendingBuffer(cap: pendingSendCap)

    init(serviceName: String, logger: Logger, onApplicationControl: ((Data) -> Void)? = nil) {
        self.serviceName = serviceName
        self.log = logger
        self.onApplicationControl = onApplicationControl
    }

    func start(onPeerConnected: (() -> Void)? = nil) {
        self.onPeerConnected = onPeerConnected
        let conn = xpc_connection_create_mach_service(
            serviceName, queue,
            UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
        )

        xpc_connection_set_event_handler(conn) { [weak self] event in
            self?.handleListenerEvent(event)
        }

        xpc_connection_activate(conn)
        listener = conn
        log.info("XPC listener started on \(self.serviceName)")
    }

    /// send enqueues an event payload for delivery to every connected peer. When no peer is connected the event is
    /// appended to the pending buffer and flushed to the next peer that completes the hello handshake. Drops oldest
    /// entries when the buffer fills (lossy FIFO) so a stuck or never-connecting agent can never OOM the extension.
    func send(data: Data) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.peers.isEmpty {
                let dropped = self.pendingBuffer.append(data)
                if dropped > 0 {
                    self.log.warning(
                        "XPC peer absent; dropped \(dropped, privacy: .public) oldest pending events (cap \(pendingSendCap, privacy: .public))"
                    )
                }
                return
            }
            self.broadcastLocked(data)
        }
    }

    // MARK: Private (all callers run on `queue`)

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

    /// flushPendingTo sends every buffered event to the freshly-connected peer in order, then clears the buffer.
    /// Sending to one peer rather than broadcasting to all peers reflects the design contract: a queued event is the
    /// same event the broadcast would have delivered, and at the moment it was queued there were no peers, so the newly
    /// arriving peer is the rightful recipient. If a SECOND peer connects later, that's a separate session and doesn't
    /// get the historical buffer.
    ///
    /// The drain happens up-front (clearing the buffer atomically on `queue`), but the sends are chunked via flushChunks
    /// so a deep buffer (worst case pendingSendCap) can't monopolise the serial queue for the whole drain and stall an
    /// inbound hello / disconnect queued behind it. In-order delivery is preserved, so the "delivers every buffered
    /// event in the order it was emitted" contract still holds.
    /// `whenDrained` runs once every buffered event has been sent to this peer, or immediately when there was nothing
    /// buffered. It does NOT run if the peer disconnected mid-drain, because there is no longer anyone to tell.
    private func flushPendingTo(_ peer: XPCPeer, whenDrained: (() -> Void)? = nil) {
        guard !pendingBuffer.isEmpty else {
            whenDrained?()
            return
        }
        let drained = pendingBuffer.drain()
        log.info("XPC flushing \(drained.count, privacy: .public) buffered events to newly-connected peer")
        flushChunks(drained[...], to: peer, whenDrained: whenDrained)
    }

    /// flushChunks sends the next flushChunkSize events from `remaining`, then re-dispatches itself on `queue` for the
    /// rest so the serial queue can interleave other work between chunks. A live event broadcast during the flush
    /// carries a later timestamp than any buffered (older) event, so the server's timestamp-ordered graph build
    /// tolerates the interleave. If the peer disconnected since the previous chunk (its ERROR handler ran on `queue` and
    /// removed it from `peers`), the remaining sends would be no-ops against a cancelled connection, so we stop early -
    /// consistent with the "stop sending events to a peer once its connection closes" disconnect-cleanup contract.
    private func flushChunks(_ remaining: ArraySlice<Data>, to peer: XPCPeer, whenDrained: (() -> Void)? = nil) {
        guard peers.contains(peer) else {
            log.info("XPC flush aborted mid-drain: peer disconnected before all buffered events were sent")
            return
        }
        let chunk = remaining.prefix(flushChunkSize)
        for data in chunk {
            let msg = xpc_dictionary_create_empty()
            data.withUnsafeBytes { buf in
                guard let baseAddress = buf.baseAddress else { return }
                xpc_dictionary_set_data(msg, "data", baseAddress, buf.count)
            }
            xpc_connection_send_message(peer.connection, msg)
        }
        let next = remaining.dropFirst(chunk.count)
        guard !next.isEmpty else {
            whenDrained?()
            return
        }
        queue.async { [weak self] in
            self?.flushChunks(next, to: peer, whenDrained: whenDrained)
        }
    }

    /// handlePeerMessage dispatches an inbound XPC dictionary from a connected peer (the agent). The decision logic
    /// lives in `dispatchInbound` so unit tests cover every reply path; this method does the XPC framework calls each
    /// verdict needs.
    private func handlePeerMessage(_ event: xpc_object_t, peer: XPCPeer) {
        let typeStr = xpc_dictionary_get_string(event, "type").map { String(cString: $0) }
        var dataLen: Int = 0
        var inboundData: Data?
        if let dataPtr = xpc_dictionary_get_data(event, "data", &dataLen), dataLen > 0 {
            inboundData = Data(bytes: dataPtr, count: dataLen)
        }

        switch dispatchInbound(type: typeStr, data: inboundData) {
        case .helloAck:
            let ack = xpc_dictionary_create_empty()
            xpc_dictionary_set_string(ack, "type", XPCMessageType.helloAck)
            xpc_connection_send_message(peer.connection, ack)
            // Receipt of hello is positive proof this peer is the real agent (not a phantom). Flush any events
            // buffered while no peer was connected so the agent picks them up immediately rather than after the
            // first natural exec.
            //
            // Level-triggered state the new peer has not seen yet (provider liveness, #649) is published from the
            // drain completion, NOT inline after this call. flushChunks only sends its first chunk synchronously and
            // re-dispatches the rest, so publishing inline would put the current snapshot ahead of any still-queued
            // chunks; a stale provider-status event replayed out of that buffer would then land last and overwrite
            // correct liveness with an older view until the next transition, which for a wedged provider never comes.
            flushPendingTo(peer) { [weak self] in
                self?.onPeerConnected?()
            }
        case .applyApplicationControl(let data):
            onApplicationControl?(data)
        case .rejectMissingData:
            log.error("application_control.update missing 'data'")
        case .ignore:
            // type is peer-supplied; redact in the unified log so a compromised peer cannot inject arbitrary strings
            // into log readers. typeStr may be nil if the peer omitted the field entirely.
            log.info("unknown XPC message type: \(typeStr ?? "(none)", privacy: .private)")
        }
    }

    private func handleListenerEvent(_ event: xpc_object_t) {
        let type = xpc_get_type(event)

        if type == XPC_TYPE_CONNECTION {
            // Validate peer code signing before accepting the connection. The agent binary must be signed with
            // --options runtime for this to work.
            let result = xpc_connection_set_peer_code_signing_requirement(event, peerCodeSigningRequirement)
            if result != 0 {
                log.error("Failed to set peer code signing requirement: \(result)")
                xpc_connection_cancel(event)
                return
            }

            let peer = XPCPeer(connection: event)
            peers.insert(peer)
            log.info("Peer connected (total: \(self.peers.count))")

            xpc_connection_set_event_handler(event) { [weak self] peerEvent in
                let peerType = xpc_get_type(peerEvent)
                if peerType == XPC_TYPE_ERROR {
                    self?.queue.async {
                        self?.peers.remove(peer)
                        self?.log.info("Peer disconnected (total: \(self?.peers.count ?? 0))")
                    }
                    return
                }
                if peerType == XPC_TYPE_DICTIONARY {
                    self?.handlePeerMessage(peerEvent, peer: peer)
                }
            }

            xpc_connection_activate(event)
            // Buffer flush is gated on receiving the peer's "hello" message rather than a time-based fallback
            // (issue #178). A real agent peer sends hello to trigger the lazy Mach port bind; a phantom peer
            // (observed in QA: connect → disconnect within ~10ms with no inbound traffic) never sends hello and
            // therefore never gets the buffer. handlePeerMessage handles the flush.
        } else if type == XPC_TYPE_ERROR {
            log.error("Listener error")
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
