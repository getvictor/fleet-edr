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
/// Updates arrive on the XPC server's queue and providers start on the framework's threads, so every transition runs on one serial
/// queue. An apply that completes after a newer one was issued is not reported, so the status always describes the latest settings.
final class NetworkContainmentController: @unchecked Sendable {
    static let shared = NetworkContainmentController()

    private let store = NetworkContainmentStore()
    private let queue = DispatchQueue(label: "com.fleetdm.edr.networkcontainment")
    /// Guarded by queue.
    private weak var provider: NEFilterDataProvider?
    private var generation = 0
    private var status: NetworkContainmentStatus?
    private let serializer = NetworkEventSerializer()

    /// baselineSettings are the filter's settings when the host is not contained.
    static func baselineSettings() -> NEFilterSettings {
        NEFilterSettings(rules: [], defaultAction: .filterData)
    }

    /// startupState is the persisted state and the settings that enforce it, for a starting filter to apply as its first settings.
    func startupState() -> (update: NetworkContainmentUpdate?, settings: NEFilterSettings) {
        let update = store.current
        return (update, update.map(Self.settings(for:)) ?? Self.baselineSettings())
    }

    /// providerStarted records the running content filter and the state its startup settings enforced. When an update was accepted
    /// while the filter was starting, the newer state is applied now.
    func providerStarted(_ filter: NEFilterDataProvider, applied: NetworkContainmentUpdate?, error: Error?) {
        queue.async {
            self.provider = filter
            guard error == nil, self.store.current == applied else {
                self.applyLocked()
                return
            }
            self.status = NetworkContainmentStatus(
                contained: applied?.contained ?? false, version: applied?.version ?? 0, epoch: applied?.epoch ?? 0, applied: true,
                error: nil
            )
            self.publishLocked()
        }
    }

    /// providerStopped forgets the filter, so an update received while it is down is persisted and applied at its next start.
    func providerStopped(_ filter: NEFilterDataProvider) {
        queue.async {
            if self.provider === filter {
                self.provider = nil
            }
        }
    }

    /// receive handles a `network_containment.update` from the agent.
    func receive(_ data: Data) {
        queue.async {
            guard let update = self.store.accept(data) else {
                logger.info("network containment update refused: not a valid document, or not newer than the current state")
                self.publishLocked()
                return
            }
            logger.info("""
            network containment update accepted: contained=\(update.contained, privacy: .public) \
            version=\(update.version, privacy: .public) epoch=\(update.epoch, privacy: .public)
            """)
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
        guard let provider else {
            status = NetworkContainmentStatus(
                contained: update?.contained ?? false, version: update?.version ?? 0, epoch: update?.epoch ?? 0, applied: false,
                error: "content filter is not running"
            )
            publishLocked()
            return
        }
        generation += 1
        let issued = generation
        let settings = update.map(Self.settings(for:)) ?? Self.baselineSettings()
        provider.apply(settings) { error in
            self.queue.async {
                guard issued == self.generation else { return }
                if let error {
                    logger.error("network containment settings not applied: \(error.localizedDescription, privacy: .public)")
                }
                self.status = NetworkContainmentStatus(
                    contained: update?.contained ?? false, version: update?.version ?? 0, epoch: update?.epoch ?? 0,
                    applied: error == nil, error: error?.localizedDescription
                )
                self.publishLocked()
            }
        }
    }

    private func publishLocked() {
        guard let status, let data = serializer.serialize(eventType: NetworkContainmentStatus.eventType, payload: status) else {
            return
        }
        XPCServer.shared.send(data: data)
    }

    /// settings turns a containment state into filter settings: the lifeline allowed and everything else dropped when contained, the
    /// baseline otherwise.
    static func settings(for update: NetworkContainmentUpdate) -> NEFilterSettings {
        let rules = NetworkContainment.lifeline(for: update)
        guard !rules.isEmpty else { return baselineSettings() }
        return NEFilterSettings(rules: rules.map { NEFilterRule(networkRule: networkRule(for: $0), action: .allow) }, defaultAction: .drop)
    }

    private static func networkRule(for rule: LifelineRule) -> NENetworkRule {
        let port = NWEndpoint.Port(rawValue: rule.port) ?? .any
        return NENetworkRule(
            remoteNetworkEndpoint: NWEndpoint.hostPort(host: NWEndpoint.Host(rule.address), port: port),
            remotePrefix: rule.prefix,
            localNetworkEndpoint: nil,
            localPrefix: 0,
            protocol: rule.transport == .tcp ? .TCP : .UDP,
            direction: rule.direction == .outbound ? .outbound : .any
        )
    }
}
