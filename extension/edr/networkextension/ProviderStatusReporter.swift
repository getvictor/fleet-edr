import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "ProviderStatus")

/// ProviderStatusReporter broadcasts which providers are running, so agent health can key on provider liveness instead
/// of on XPC connectivity (issue #649).
///
/// It rides the existing event channel rather than a second XPC message kind. The agent's C bridge forwards any inbound
/// dictionary carrying a `data` blob to the Go event callback and ignores everything else, so a dedicated message kind
/// would mean changing the bridge, the cgo callbacks and the non-darwin stub for a payload the agent consumes locally
/// and never uploads. Instead the payload is a normal, well-formed event envelope with a control `event_type`; the
/// agent recognises that type, updates health and drops it before the upload queue. Nothing on the server rejects an
/// unrecognised type, so the worst case for a version-skewed agent that forwarded one is a single odd stored row rather
/// than a failed batch.
///
/// Concurrency: the two providers start and stop on the framework's own threads, so the state is guarded by a lock. The
/// broadcast happens outside the lock, because `send` hops to the XPC server's serial queue and holding a lock across
/// that is how deadlocks get built.
final class ProviderStatusReporter {
    /// The control event type the agent filters on. Wire contract: changing it silently stops health from ever leaving
    /// "awaiting provider status", so it is duplicated in the agent's constant with a comment pointing here.
    static let eventType = "ne_provider_status"

    private let lock = NSLock()
    private var liveness = ProviderLiveness()
    private let broadcast: (Data) -> Void
    private let serialize: (ProviderStatusPayload) -> Data?

    init(broadcast: @escaping (Data) -> Void, serialize: @escaping (ProviderStatusPayload) -> Data?) {
        self.broadcast = broadcast
        self.serialize = serialize
    }

    /// recordStarted notes that a provider is now capturing.
    func recordStarted(_ provider: ProviderLiveness.Provider) {
        lock.lock()
        let changed = liveness.record(provider, .running)
        lock.unlock()
        guard changed else { return }
        logger.info("Provider \(provider.rawValue, privacy: .public) is running")
        publish()
    }

    /// recordStopped notes that a provider stopped, and grades it by WHY it stopped and WHICH provider it was.
    ///
    /// A stop graded as deliberate absence drops the provider from the report entirely, so it reads as "never started"
    /// rather than as a fault. That covers session lifecycle for either provider (logout, user switch, a superceded
    /// configuration) and an operator switching off the opt-in DNS proxy, which is a supported configuration rather than
    /// a degradation. An operator switching off the mandatory content filter is NOT absence: it is reported stopped, so
    /// a host that has been quietly stripped of network capture is visible. Any other reason is a fault for either
    /// provider, which is the shape the 2026-07-17 incident took.
    func recordStopped(_ provider: ProviderLiveness.Provider, reason: Int) {
        let deliberate = ProviderLiveness.isDeliberateAbsence(provider: provider, reason: reason)
        lock.lock()
        let changed = deliberate ? liveness.forget(provider) : liveness.record(provider, .stopped)
        lock.unlock()
        guard changed else { return }
        let grading = deliberate ? "deliberately disabled" : "a fault"
        logger.info("""
        Provider \(provider.rawValue, privacy: .public) stopped (reason \(reason, format: .decimal)); treating it as \
        \(grading, privacy: .public)
        """)
        publish()
    }

    /// publish re-broadcasts the current snapshot. Called on every provider transition and again whenever an agent
    /// completes the hello handshake, because this state is level-triggered: an agent that connects minutes after the
    /// providers started would otherwise wait for a transition that never comes.
    func publish() {
        lock.lock()
        let snapshot = liveness.snapshot
        lock.unlock()
        guard let data = serialize(ProviderStatusPayload(providers: snapshot)) else {
            logger.error("Could not serialize provider status; agent health stays degraded until a later report arrives")
            return
        }
        broadcast(data)
    }
}
