import Foundation

/// ProviderLiveness tracks which of the network extension's providers are actually running, so the agent can report
/// health on provider liveness rather than on XPC connectivity.
///
/// Why this exists (issue #649). The XPC listener starts in `main.swift` BEFORE
/// `NEProvider.startSystemExtensionMode()`, so the agent can connect to an extension process in which no provider has
/// started, or ever will. That is not hypothetical: on 2026-07-17 a disable/re-enable of the network extension from
/// System Settings relaunched the process with neither provider starting (the DNS proxy torn down with
/// `NEAgentErrorDomain Code=2`, the filter session ending with "configuration has been removed"), the agent reconnected,
/// health went green, and the host produced no `network_connect` or `dns_query` events for 24+ hours with no signal
/// anywhere. The same shape recurred repeatedly during the issue's own QA whenever an activation half-failed.
///
/// What it deliberately does NOT catch: a provider that started and then wedged while still reporting itself running.
/// The second manifestation in #649 was exactly that (a DNS proxy session stuck on "a pending start command already
/// exists" while claiming state `Running`). No signal available inside the provider distinguishes that from an idle
/// host, so detecting it needs data-flow evidence (network telemetry stops while exec telemetry continues), which is
/// server-side work and belongs with the telemetry-loss alerting in #348.
///
/// Pure Foundation, no NetworkExtension import, so the state machine and its wire shape are unit-testable without a
/// live provider session.
struct ProviderLiveness {
    /// The providers this extension can run. Raw values are the wire identifiers the agent keys health on; they are a
    /// stable contract, so renaming one is a wire change.
    enum Provider: String, CaseIterable, Codable, Sendable {
        case contentFilter = "content_filter"
        case dnsProxy = "dns_proxy"
    }

    /// A provider's last observed lifecycle state. There is deliberately no "unknown": a provider we have never seen
    /// start is simply absent from the report, which is what lets the agent distinguish "never started" from "started
    /// then stopped".
    enum State: String, Codable, Sendable {
        case running
        case stopped
    }

    private(set) var states: [Provider: State] = [:]

    /// `NEProviderStopReason` raw values, mirrored as integers so this type stays free of the NetworkExtension import
    /// and therefore unit-testable. Only the reasons this rule cares about are named; the rest are faults by default.
    enum StopReason {
        static let userInitiated = 1
        static let providerDisabled = 5
        static let configurationDisabled = 9
        static let configurationRemoved = 10
        static let superceded = 11
        static let userLogout = 12
        static let userSwitch = 13
    }

    /// Stop reasons that mean somebody turned this provider off on purpose, as opposed to it failing. A deliberate stop
    /// makes the provider ABSENT from the report rather than `stopped`, because DNS proxying in particular is opt-in:
    /// a host that has deliberately disabled it must not read as unhealthy forever.
    ///
    /// Everything else (providerFailed, noNetworkAvailable, configurationFailed, connectionFailed, ...) is a fault and
    /// reports `stopped`, which is what the 2026-07-17 incident looked like from the outside.
    static let deliberateStopReasons: Set<Int> = [
        StopReason.userInitiated, StopReason.providerDisabled, StopReason.configurationDisabled,
        StopReason.configurationRemoved, StopReason.superceded, StopReason.userLogout, StopReason.userSwitch
    ]

    static func isDeliberateStop(reason: Int) -> Bool {
        deliberateStopReasons.contains(reason)
    }

    /// forget drops a provider from the report entirely, so it grades as "never started" rather than "stopped". Used
    /// for a deliberate stop.
    @discardableResult
    mutating func forget(_ provider: Provider) -> Bool {
        states.removeValue(forKey: provider) != nil
    }

    /// record marks a provider's new state and reports whether that changed anything, so the caller only broadcasts on
    /// a real transition rather than on every start/stop callback the framework happens to deliver.
    @discardableResult
    mutating func record(_ provider: Provider, _ state: State) -> Bool {
        guard states[provider] != state else { return false }
        states[provider] = state
        return true
    }

    /// snapshot renders the wire payload: provider identifier to state, for every provider observed so far. A provider
    /// that has never started is omitted rather than reported as stopped, because "we have never seen it" and "it ran
    /// and went away" are different situations for an operator and the agent grades them differently.
    var snapshot: [String: String] {
        var out: [String: String] = [:]
        for (provider, state) in states {
            out[provider.rawValue] = state.rawValue
        }
        return out
    }

    /// anyRunning is the coarse question the agent's grace period keys on: has ANY provider reported itself running?
    /// A process with none is the failure this whole mechanism exists to surface.
    var anyRunning: Bool {
        states.values.contains(.running)
    }
}

/// The wire payload the extension broadcasts. Rides the existing event channel as a normal envelope (see
/// `ProviderStatusReporter`), because the XPC bridge forwards any message carrying a `data` blob to the agent and a
/// second channel would mean changing the C bridge for a message the agent consumes locally.
struct ProviderStatusPayload: Codable, Sendable {
    /// Provider identifier to state, e.g. `["content_filter": "running"]`.
    let providers: [String: String]

    enum CodingKeys: String, CodingKey {
        case providers
    }
}
