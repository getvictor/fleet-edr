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
    /// What a starting content filter needs: the state it must enforce, the settings that do, and the resolvers those settings name,
    /// which it hands back when it has started.
    struct StartupState {
        let update: NetworkContainmentUpdate?
        let settings: NEFilterSettings
        let resolvers: [String]
    }

    static let shared = NetworkContainmentController()

    private let store = NetworkContainmentStore()
    private let queue = DispatchQueue(label: "com.fleetdm.edr.networkcontainment")
    private let serializer = NetworkEventSerializer()
    // Everything below is guarded by queue.
    private let sequencer = ContainmentSequencer<NEFilterDataProvider>()
    private var tracker = ContainmentStatusTracker()
    private var released = ReleasedLifeline()
    private var resolverLifeline = ResolverLifeline()
    /// Re-reads the host's configured resolvers while a host is contained. The cache refreshes only when it is read, and the only
    /// reads are the ones that build settings, so without this the list would be re-read at whatever cadence the agent happens to
    /// refresh the lifeline at, and not at all while the agent is down. The rules name those addresses, so a host that changed
    /// network would keep rules for resolvers it can no longer reach.
    private var resolverWatch: DispatchSourceTimer?
    /// The host's configured resolvers, which are the only DNS the lifeline allows (issue #1069). Read here rather than taken from
    /// the DNS proxy because containment does not require the proxy to be running, which is the case the restriction exists for.
    private let resolvers = SystemResolverCache()

    private init() {
        // A read publishes a list the rules name, so settings that allowed the previous resolvers are re-applied against the new
        // ones. Only while contained: a host that is not contained has no lifeline rules to move.
        resolvers.onRefresh = { [weak self] _ in
            guard let self else { return }
            self.queue.async {
                guard self.store.current?.contained == true else { return }
                // Not a containment change: with no filter running there is nothing to report as failed, and the list is picked up by
                // the comparison a starting filter makes.
                self.applyLocked(forResolverChange: true)
            }
        }
    }

    /// How often a contained host's configured resolvers are re-read. Short enough that a host that changed network resolves again
    /// without waiting for an operator, long enough that the steady cost is one configd read a minute.
    private static let resolverWatchSeconds = 60
    private static var resolverWatchInterval: DispatchTimeInterval { .seconds(resolverWatchSeconds) }

    /// baselineSettings are the filter's settings when the host is not contained.
    static func baselineSettings() -> NEFilterSettings {
        NEFilterSettings(rules: [], defaultAction: .filterData)
    }

    /// startupState is the persisted state, the settings that enforce it, and the resolvers those settings name, for a starting filter
    /// to apply as its first settings. The caller hands the resolvers back to providerStarted: they belong to that filter's startup
    /// rather than to the extension, because a filter replacing another can finish starting after an apply to the old one, and what
    /// decides whether the new filter needs the current list is the list THIS filter started with.
    func startupState() -> StartupState {
        // Warm the resolver list while the filter starts, so a containment applied moments later already has the DNS half of its
        // lifeline. A cold read costs the host nothing lasting: the refresh re-applies the settings when it lands.
        resolvers.prime()
        // On the queue, so a release accepted after these settings were chosen is ordered after the kept rules were reset.
        return queue.sync {
            let update = store.current
            released.filterStarting(with: update)
            let snapshot = self.resolvers.addresses()
            self.watchResolversLocked()
            let settings = update.map { Self.settings(for: $0, released: [], resolvers: snapshot) } ?? Self.baselineSettings()
            return StartupState(update: update, settings: settings, resolvers: snapshot)
        }
    }

    /// providerStarted records the running content filter and the state its startup settings enforced. When an update was accepted
    /// while the filter was starting, or an apply is still in flight, the current state is applied to it. A filter whose startup
    /// settings failed is rejected by the framework, so it is not recorded, and the failure is reported.
    func providerStarted(_ filter: NEFilterDataProvider, applied: NetworkContainmentUpdate?, resolvers startupResolvers: [String],
                         error: Error?) {
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
                // This filter's settings are the ones in force, so what they name is what the extension holds. Recorded here rather
                // than when they were built: a filter that never starts, or one replaced by another, never held anything.
                self.resolverLifeline.recordApplied(startupResolvers)
                // They were built from the resolvers known when this filter started. A read that landed while it was starting, or a
                // list that moved while no filter was running, is applied now.
                if self.store.current?.contained == true, self.resolverLifeline.needsApply(for: self.resolvers.addresses()) {
                    self.applyLocked()
                }
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
            guard let update = self.store.accept(data) else {
                logger.info("""
                network containment update refused: not a valid document, not newer than the current state, or not persisted
                """)
                self.publishLocked()
                return
            }
            self.tracker.pending()
            self.watchResolversLocked()
            self.released.accepted(update)
            logger.info("""
            network containment update accepted: contained=\(update.contained, privacy: .public) \
            version=\(update.version, privacy: .public) epoch=\(update.epoch, privacy: .public)
            """)
            // Reported as pending now, so a change is visible even while an earlier apply is still in flight.
            self.publishLocked()
            self.applyLocked()
        }
    }

    /// dnsDecision is what the DNS proxy does with a query datagram under the held containment state. Safe from any thread: the store
    /// guards its state.
    func dnsDecision(for datagram: Data) -> ContainedDNS.Decision {
        ContainedDNS.decision(for: datagram, containment: store.current)
    }

    /// isContained reports whether the held state contains the host. Safe from any thread.
    var isContained: Bool {
        store.current?.contained ?? false
    }

    /// publish re-broadcasts the current status. Called when an agent completes the hello handshake: the status is level-triggered,
    /// so an agent that connects after containment was applied must be told rather than wait for the next change.
    func publish() {
        queue.async { self.publishLocked() }
    }

    private func applyLocked(forResolverChange: Bool = false) {
        let update = store.current
        switch sequencer.requestApply() {
        case .deferred:
            return
        case .noFilter:
            // A resolver list that moved with no filter running leaves the recorded snapshot stale on purpose: the next filter to
            // start compares against it and applies the current list. The held state is unchanged, so it is not a failure.
            guard !forResolverChange else { return }
            tracker.failed("content filter is not running")
            publishLocked()
        case .apply(let target):
            let resolverAddresses = resolvers.addresses()
            if update?.contained == true {
                // The DNS half of the lifeline is the host's own configuration rather than anything the server sent, so it is worth
                // saying which addresses it came to on the host itself.
                let allowed = resolverAddresses.isEmpty ? "none" : resolverAddresses.joined(separator: ",")
                logger.info("network containment: DNS allowed to the configured resolvers: \(allowed, privacy: .public)")
            }
            resolverLifeline.recordApplied(resolverAddresses)
            let settings = update.map { Self.settings(for: $0, released: released.rules, resolvers: resolverAddresses) }
                ?? Self.baselineSettings()
            target.apply(settings) { error in
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
    /// watchResolversLocked keeps the configured resolvers under observation while the host is contained, and stops when it is not.
    /// A read that publishes a different list re-applies the settings through onRefresh; one that publishes the same list does
    /// nothing, so the steady state costs one dynamic-store read per interval and no applies.
    private func watchResolversLocked() {
        guard store.current?.contained == true else {
            resolverWatch?.cancel()
            resolverWatch = nil
            return
        }
        guard resolverWatch == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.resolverWatchInterval, repeating: Self.resolverWatchInterval)
        timer.setEventHandler { [weak self] in self?.resolvers.prime() }
        timer.resume()
        resolverWatch = timer
    }

    private func publishLocked() {
        guard let held = store.current else { return }
        // Asked at publish time rather than remembered: whether names are filtered is the DNS proxy's current state, and the proxy can
        // stop or be disabled long after a containment was applied.
        let status = tracker.status(held: held, namesFiltered: ProviderStatus.shared.isRunning(.dnsProxy))
        guard let data = serializer.serialize(eventType: NetworkContainmentStatus.eventType, payload: status) else { return }
        XPCServer.shared.send(data: data)
    }

    /// settings turns a containment state into filter settings: the lifeline allowed and everything else dropped when contained, and
    /// otherwise the baseline's hand-every-flow-to-the-provider with the released server flows still allowed (see ReleasedLifeline).
    static func settings(for update: NetworkContainmentUpdate, released: [LifelineRule], resolvers: [String]) -> NEFilterSettings {
        guard update.contained else {
            return NEFilterSettings(rules: allowRules(released), defaultAction: .filterData)
        }
        let lifeline = NetworkContainment.lifeline(for: update, resolvers: resolvers)
        return NEFilterSettings(rules: allowRules(lifeline), defaultAction: .drop)
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
