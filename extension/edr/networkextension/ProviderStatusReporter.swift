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
    private let disabledStore: DisabledProviderStore

    init(broadcast: @escaping (Data) -> Void, serialize: @escaping (ProviderStatusPayload) -> Data?,
         disabledStore: DisabledProviderStore = DisabledProviderStore()) {
        self.broadcast = broadcast
        self.serialize = serialize
        self.disabledStore = disabledStore
        // Seeded before the first publish, because a provider that is switched off never starts and so never stops: nothing in this
        // process's lifetime would otherwise say it was turned off on purpose (issue #1078). A provider that IS running corrects this
        // within seconds, when its start callback records it, so a stale entry costs only that.
        for name in disabledStore.load() {
            guard let provider = ProviderLiveness.Provider(rawValue: name) else { continue }
            liveness.record(provider, .disabled)
        }
    }

    /// persistDisabledLocked writes which providers are currently switched off, so a later extension process starts knowing. Caller
    /// holds the lock. A write failure is logged and nothing else: this process's own report is already correct.
    private func persistDisabledLocked() {
        var disabled: Set<String> = []
        for provider in ProviderLiveness.Provider.allCases where liveness.states[provider] == .disabled {
            disabled.insert(provider.rawValue)
        }
        if !disabledStore.save(disabled) {
            logger.error("could not record which capture providers are switched off; a restart will not remember")
        }
    }

    /// recordStarted notes that a provider is now capturing.
    func recordStarted(_ provider: ProviderLiveness.Provider) {
        lock.lock()
        let changed = liveness.record(provider, .running)
        // A provider that is capturing is not switched off, whatever an earlier process recorded, so the memory is cleared here
        // rather than only on an explicit enable: this is the path that corrects a stale entry.
        persistDisabledLocked()
        lock.unlock()
        guard changed else { return }
        logger.info("Provider \(provider.rawValue, privacy: .public) is running")
        publish()
    }

    /// recordStopped notes that a provider stopped, and grades it by WHY it stopped and WHICH provider it was.
    ///
    /// Three outcomes, not two. A SESSION LIFECYCLE stop (logout, user switch, a superceded configuration) drops the provider from
    /// the report entirely, so it reads as "never started" rather than as a fault. An operator switching off the opt-in DNS proxy
    /// records `disabled` and persists it, because that is a supported configuration that still has to be visible: a contained host
    /// whose proxy is off is not restricting which names it looks up (issue #1078). Anything else records `stopped`, the fault,
    /// which is the shape the 2026-07-17 incident took. An operator switching off the mandatory content filter takes that last
    /// branch rather than the disabled one, so a host quietly stripped of network capture stays visible as a fault.
    func recordStopped(_ provider: ProviderLiveness.Provider, reason: Int) {
        let after = ProviderLiveness.stateAfterStop(provider: provider, reason: reason)
        lock.lock()
        // A fault carries its reason, so a detection consumer can discriminate for itself; a deliberate disable carries none, because
        // there is nothing to discriminate and the state says all of it.
        let changed: Bool
        switch after {
        case nil: changed = liveness.forget(provider)
        case .stopped: changed = liveness.record(provider, .stopped, reason: reason)
        case let .some(state): changed = liveness.record(provider, state)
        }
        persistDisabledLocked()
        lock.unlock()
        guard changed else { return }
        let grading: String
        switch after {
        case nil: grading = "a lifecycle stop"
        case .disabled: grading = "deliberately disabled"
        default: grading = "a fault"
        }
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
        let reasons = liveness.reasonSnapshot
        lock.unlock()
        guard let data = serialize(ProviderStatusPayload(providers: snapshot, stopReasons: reasons)) else {
            logger.error("Could not serialize provider status; agent health stays degraded until a later report arrives")
            return
        }
        broadcast(data)
    }
}
