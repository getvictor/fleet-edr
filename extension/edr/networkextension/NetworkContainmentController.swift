import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "NetworkContainment")

/// NetworkContainmentController applies host network containment as content-filter settings and reports what it applied (#948).
///
/// Contained, the filter's settings allow the lifeline and drop everything else, a decision the operating system enforces without
/// consulting this provider. That is what cuts established connections and what keeps containment in force while the provider is
/// stopped or restarting. Not contained, the settings are the ones the filter has always used: every flow is handed to handleNewFlow
/// and allowed after its telemetry is emitted. While contained the filter therefore records no network_connect events.
///
/// Updates arrive on the XPC server's queue and providers start and stop on the framework's threads, so every transition runs on one
/// serial queue. Applies are serialized as well: one is in flight at a time, and an update that arrives meanwhile is applied when it
/// completes, so settings can never take effect out of order. A result from a filter that has since stopped or been replaced is not
/// reported, since it no longer describes the host. ContainmentSequencer holds that bookkeeping.
final class NetworkContainmentController: @unchecked Sendable {
    static let shared = NetworkContainmentController()

    private let store = NetworkContainmentStore()
    private let queue = DispatchQueue(label: "com.fleetdm.edr.networkcontainment")
    private let serializer = NetworkEventSerializer()
    // Everything below is guarded by queue.
    private let sequencer = ContainmentSequencer<NEFilterDataProvider>()
    private var tracker = ContainmentStatusTracker()
    private var released = ReleasedLifeline()

    /// baselineSettings are the filter's settings when the host is not contained.
    static func baselineSettings() -> NEFilterSettings {
        NEFilterSettings(rules: [], defaultAction: .filterData)
    }

    /// startupState is the persisted state and the settings that enforce it, for a starting filter to apply as its first settings.
    func startupState() -> (update: NetworkContainmentUpdate?, settings: NEFilterSettings) {
        let update = store.current
        return (update, update.map { Self.settings(for: $0, released: []) } ?? Self.baselineSettings())
    }

    /// providerStarted records the running content filter and the state its startup settings enforced. When an update was accepted
    /// while the filter was starting, or an apply is still in flight, the current state is applied to it. A filter whose startup
    /// settings failed is rejected by the framework, so it is not recorded, and the failure is reported.
    func providerStarted(_ filter: NEFilterDataProvider, applied: NetworkContainmentUpdate?, error: Error?) {
        queue.async {
            if let error {
                // The framework rejects a filter whose startup settings failed, so it never becomes the target.
                self.sequencer.stopped(filter)
                self.tracker.failed(error.localizedDescription)
                self.publishLocked()
                return
            }
            switch self.sequencer.started(filter, startupEnforcesCurrent: self.store.current == applied) {
            case .ignore:
                return
            case .wait:
                // The held state is applied to this filter when the apply in flight completes.
                self.tracker.pending()
                self.publishLocked()
            case .apply:
                self.tracker.pending()
                self.publishLocked()
                self.applyLocked()
            case .report:
                self.tracker.confirmed(applied)
                self.publishLocked()
            }
        }
    }

    /// providerStopped forgets the filter, so an update received while it is down is persisted and applied at its next start.
    func providerStopped(_ filter: NEFilterDataProvider) {
        queue.async {
            // With no filter running nothing is confirmed to enforce the held state, so the status stops saying it is applied until
            // a filter starts and confirms it again. A late stop from a filter already replaced leaves its replacement's status alone.
            guard self.sequencer.stopped(filter) else { return }
            self.tracker.failed("content filter is not running")
            self.publishLocked()
        }
    }

    /// receive handles a `network_containment.update` from the agent.
    func receive(_ data: Data) {
        queue.async {
            let held = self.store.current
            guard let update = self.store.accept(data) else {
                logger.info("""
                network containment update refused: not a valid document, not newer than the current state, or not persisted
                """)
                self.publishLocked()
                return
            }
            self.tracker.pending()
            self.released.accepted(update, releasing: held)
            logger.info("""
            network containment update accepted: contained=\(update.contained, privacy: .public) \
            version=\(update.version, privacy: .public) epoch=\(update.epoch, privacy: .public)
            """)
            // Reported as pending now, so a change is visible even while an earlier apply is still in flight.
            self.publishLocked()
            self.applyLocked()
        }
    }

    /// publish re-broadcasts the current status. Called when an agent completes the hello handshake: the status is level-triggered,
    /// so an agent that connects after containment was applied must be told rather than wait for the next change.
    func publish() {
        queue.async { self.publishLocked() }
    }

    private func applyLocked() {
        let update = store.current
        switch sequencer.requestApply() {
        case .deferred:
            return
        case .noFilter:
            tracker.failed("content filter is not running")
            publishLocked()
        case .apply(let target):
            target.apply(update.map { Self.settings(for: $0, released: released.rules) } ?? Self.baselineSettings()) { error in
                self.queue.async {
                    if let error {
                        logger.error("network containment settings not applied: \(error.localizedDescription, privacy: .public)")
                    }
                    let outcome = self.sequencer.completed(target)
                    if outcome.report {
                        if let error {
                            self.tracker.failed(error.localizedDescription)
                        } else {
                            self.tracker.confirmed(update)
                        }
                        self.publishLocked()
                    }
                    if outcome.applyAgain {
                        self.applyLocked()
                    }
                }
            }
        }
    }

    /// publishLocked sends the status of the held state. Nothing is sent before a containment state exists, so a host that has never
    /// been contained sends no status an agent without containment support would upload as telemetry.
    private func publishLocked() {
        guard let held = store.current else { return }
        let status = tracker.status(held: held)
        guard let data = serializer.serialize(eventType: NetworkContainmentStatus.eventType, payload: status) else { return }
        XPCServer.shared.send(data: data)
    }

    /// settings turns a containment state into filter settings: the lifeline allowed and everything else dropped when contained, and
    /// otherwise the baseline's hand-every-flow-to-the-provider with the released server flows still allowed (see ReleasedLifeline).
    static func settings(for update: NetworkContainmentUpdate, released: [LifelineRule]) -> NEFilterSettings {
        guard update.contained else {
            return NEFilterSettings(rules: allowRules(released), defaultAction: .filterData)
        }
        return NEFilterSettings(rules: allowRules(NetworkContainment.lifeline(for: update)), defaultAction: .drop)
    }

    private static func allowRules(_ rules: [LifelineRule]) -> [NEFilterRule] {
        rules.map { NEFilterRule(networkRule: networkRule(for: $0), action: .allow) }
    }

    private static func networkRule(for rule: LifelineRule) -> NENetworkRule {
        // The ports are nonzero: the server port is validated when the document is decoded and the DHCP and DNS ports are constants.
        let port = NWEndpoint.Port(integerLiteral: rule.port)
        let local = rule.localPort.map {
            NWEndpoint.hostPort(host: NWEndpoint.Host(rule.address), port: NWEndpoint.Port(integerLiteral: $0))
        }
        return NENetworkRule(
            remoteNetworkEndpoint: NWEndpoint.hostPort(host: NWEndpoint.Host(rule.address), port: port),
            remotePrefix: rule.prefix,
            localNetworkEndpoint: local,
            localPrefix: 0,
            protocol: rule.transport == .tcp ? .TCP : .UDP,
            direction: rule.direction == .outbound ? .outbound : .any
        )
    }
}
