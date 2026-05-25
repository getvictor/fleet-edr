// Pure-logic types extracted from main.swift for the host-app-extension-manager spec contract.
//
// Why this file exists separately from main.swift:
//
// main.swift carries file-scope executable code (`let action = CommandLine.arguments…`, the top-level
// switch on `action`) which is legal only in an executable target's entry-point file. The SwiftPM
// EDRExtensionLogic target is a LIBRARY, so it cannot include main.swift. To make the host-app's
// state-machine + subcommand-dispatch contract unit-testable we host the pure-logic types here, then
// import them from XCTest. main.swift implements the same contract in line with the OSSystemExtensionRequest
// delegate callbacks + NEFilterManager / NEDNSProxyManager calls; the Xcode pbxproj stays unchanged because
// this file is consumed only by SwiftPM tests, not by the production edr executable target.
//
// Contract: future changes to the host-app behavior MUST update both surfaces.
//   1. main.swift production code (ExtensionManager class, enableContentFilter / disableContentFilter,
//      enableDNSProxy / disableDNSProxy, the top-level switch).
//   2. This file's types AND the XCTest functions that assert the spec contract against them.
// A spec-test that diverges from main.swift's behavior would be a marker that overclaims; CI's system / VM
// rehearsal layer (docs/testing-strategy.md) is the line of defense that catches the production-code side
// regressing away from the contract these tests pin.

import Foundation

/// Documented system extension bundle identifiers the host app drives. Mirrored from main.swift's file-scope
/// `esfExtensionID` / `netExtensionID` constants so tests can assert the activate / deactivate flow targets
/// exactly these two extensions and no others.
enum HostAppExtensionID {
    static let endpointSecurity = "com.fleetdm.edr.securityextension"
    static let networkExtension = "com.fleetdm.edr.networkextension"
    static let all: [String] = [endpointSecurity, networkExtension]
}

/// HostAppAction is the typed subcommand the host-app CLI dispatches on. CommandLine.arguments[1] is parsed
/// into this enum before the top-level switch runs. The raw values match the CLI surface exposed to
/// operators + MDM scripts.
enum HostAppAction: String, Equatable, CaseIterable, Sendable {
    case activate
    case deactivate
    case enableFilter = "enable-filter"
    case disableFilter = "disable-filter"
    case enableDNSProxy = "enable-dns-proxy"
    case disableDNSProxy = "disable-dns-proxy"
    case notify
}

/// parseHostAppAction maps an argv string (or nil for "no subcommand provided") to a HostAppAction. The
/// default when no argument is supplied is `.activate`, matching main.swift's
/// `CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "activate"` shape.
func parseHostAppAction(_ arg: String?) -> HostAppAction {
    guard let arg, !arg.isEmpty else { return .activate }
    return HostAppAction(rawValue: arg) ?? .activate
}

/// CompletionOutcome is the per-request verdict the OSSystemExtensionRequest delegate folds into the host
/// app's aggregate. Cases mirror `OSSystemExtensionRequest.Result` plus the explicit failure path the
/// `didFailWithError` callback drives.
enum CompletionOutcome: Equatable, Sendable {
    /// `request(_:didFinishWithResult: .completed)` callback.
    case completed
    /// `request(_:didFinishWithResult: .willCompleteAfterReboot)` callback.
    case willCompleteAfterReboot
    /// `request(_:didFailWithError:)` callback (or the `@unknown default` arm in `didFinishWithResult`).
    case failed
}

/// AggregateVerdict is the overall result after EVERY expected request has reported. Drives the exit code
/// + the post-completion side effect (enable filter on activate; nothing on deactivate).
enum AggregateVerdict: Equatable, Sendable {
    /// Every request completed and none required a reboot.
    case allSucceeded
    /// At least one request will-complete-after-reboot; none failed. Per the spec, the host app
    /// MUST exit successfully so the activation is not retried prematurely.
    case rebootRequired
    /// At least one request failed.
    case anyFailed
}

/// CompletionAggregator tracks N parallel extension-request outcomes and produces a single verdict when
/// every expected request has reported. The host-app uses one with expected=2 (esfExtensionID +
/// netExtensionID); a future tier with three or more extensions would construct one with the higher count.
struct CompletionAggregator {
    let expected: Int
    private(set) var outcomes: [CompletionOutcome] = []

    init(expected: Int) {
        precondition(expected > 0, "CompletionAggregator: expected must be > 0")
        self.expected = expected
    }

    /// record adds an outcome to the aggregate. Returns true when every expected request has reported
    /// (the caller can then safely read `verdict`). Over-recording trips a precondition: in production the
    /// OSSystemExtensionRequest delegate fires didFinishWithResult OR didFailWithError exactly once per
    /// submitted request, so a record() call past `expected` is a logic error (likely a double-decrement
    /// in pendingCount or a duplicate request submission).
    @discardableResult
    mutating func record(_ outcome: CompletionOutcome) -> Bool {
        precondition(outcomes.count < expected,
                     "CompletionAggregator: cannot record more than \(expected) outcomes")
        outcomes.append(outcome)
        return outcomes.count >= expected
    }

    /// verdict returns the aggregate result. Precondition: every expected outcome has been recorded
    /// (`isComplete == true`). Precedence: any failure dominates (`.anyFailed`); otherwise any
    /// will-complete-after-reboot dominates (`.rebootRequired`); otherwise `.allSucceeded`. The
    /// precondition catches callers that read the verdict before all delegate callbacks have fired —
    /// silently returning `.allSucceeded` in that window would mask a pending failure and lead to a
    /// premature `enableContentFilter()` call on the activate path.
    var verdict: AggregateVerdict {
        precondition(isComplete, "CompletionAggregator: cannot query verdict before isComplete == true")
        if outcomes.contains(.failed) { return .anyFailed }
        if outcomes.contains(.willCompleteAfterReboot) { return .rebootRequired }
        return .allSucceeded
    }

    var isComplete: Bool { outcomes.count >= expected }
}

/// hostAppExitCode maps an AggregateVerdict to the documented host-app exit-status contract. Spec calls
/// out: "the exit status MUST reflect failure if any submitted request reports an error" and "exits
/// successfully so the activation is not retried prematurely" for the reboot-required path.
func hostAppExitCode(for verdict: AggregateVerdict) -> Int32 {
    switch verdict {
    case .anyFailed:
        return Int32(EXIT_FAILURE)
    case .allSucceeded, .rebootRequired:
        return Int32(EXIT_SUCCESS)
    }
}

/// PostAggregateStep is what the host-app does after the activate / deactivate aggregate clears. Activate
/// chains into enabling the content filter on success; deactivate exits immediately; any failure short-
/// circuits to exit regardless of subcommand.
enum PostAggregateStep: Equatable, Sendable {
    case enableContentFilter
    case exitImmediately
}

/// postAggregateStep returns the next step the host-app drives after every extension request has reported.
/// Mirrors the `if hadFailure { exit FAILURE } else if action != deactivate { enableContentFilter() } else
/// { exit SUCCESS }` branch in main.swift's `request(_:didFinishWithResult:)` delegate callback.
func postAggregateStep(for action: HostAppAction, verdict: AggregateVerdict) -> PostAggregateStep {
    if verdict == .anyFailed { return .exitImmediately }
    if action == .activate { return .enableContentFilter }
    return .exitImmediately
}

/// SubcommandIntent is the typed side-effect a single host-app subcommand invocation produces. The
/// production code in main.swift translates each subcommand into the equivalent OSSystemExtensionRequest
/// or NEManager mutation; the intents here are a pure-data view of that contract so tests can assert
/// "this subcommand toggles ONLY the filter, not the extension installation."
enum SubcommandIntent: Equatable, Sendable {
    case submitActivationRequest(extensionID: String)
    case submitDeactivationRequest(extensionID: String)
    case setContentFilterEnabled(Bool)
    case setDNSProxyEnabled(Bool)
    case runNotifyMode
}

/// intents returns the ordered list of intents a host-app subcommand expands into. Activation submits a
/// request per extension AND triggers a post-aggregate enable-filter; deactivation submits a request per
/// extension and stops. The filter / DNS-proxy subcommands toggle one piece of state and intentionally do
/// NOT activate or deactivate the extensions (the spec's "MUST NOT" clauses are encoded in the empty
/// no-extension-request prefix here).
func intents(for action: HostAppAction) -> [SubcommandIntent] {
    switch action {
    case .activate:
        var out: [SubcommandIntent] = HostAppExtensionID.all.map(SubcommandIntent.submitActivationRequest)
        out.append(.setContentFilterEnabled(true))
        return out
    case .deactivate:
        return HostAppExtensionID.all.map(SubcommandIntent.submitDeactivationRequest)
    case .enableFilter:
        return [.setContentFilterEnabled(true)]
    case .disableFilter:
        return [.setContentFilterEnabled(false)]
    case .enableDNSProxy:
        return [.setDNSProxyEnabled(true)]
    case .disableDNSProxy:
        return [.setDNSProxyEnabled(false)]
    case .notify:
        return [.runNotifyMode]
    }
}

/// FilterConfigIntent is the contract main.swift's `enableContentFilter` saves into NEFilterManager's
/// preferences. The shape mirrors the NEFilterProviderConfiguration the host-app builds; representing it
/// here lets tests assert the persisted-config contract without depending on NEFilterManager's runtime
/// callbacks. The reboot-recovery spec scenario hinges on these fields surviving across reboots — macOS
/// owns that persistence; the host-app's job is to call saveToPreferences() with these values set.
struct FilterConfigIntent: Equatable, Sendable {
    let filterSockets: Bool
    let filterPackets: Bool
    let localizedDescription: String
    let isEnabled: Bool
}

/// activateFilterConfig is the FilterConfigIntent main.swift writes during activate. socket-only,
/// no-packet-capture, with a descriptive label visible in System Settings → Network → Filters. Toggling
/// `enable-filter` reuses the same config with isEnabled=true; `disable-filter` flips just the isEnabled
/// bit. Persisted via NEFilterManager.shared().saveToPreferences().
let activateFilterConfig = FilterConfigIntent(
    filterSockets: true,
    filterPackets: false,
    localizedDescription: "Fleet EDR Network Monitor",
    isEnabled: true
)

/// DNSProxyConfigIntent is the contract main.swift's `enableDNSProxy` saves into NEDNSProxyManager's
/// preferences. providerBundleIdentifier MUST match the network extension's bundle id so the OS knows
/// which extension target the DNS proxy provider belongs to.
struct DNSProxyConfigIntent: Equatable, Sendable {
    let providerBundleIdentifier: String
    let localizedDescription: String
    let isEnabled: Bool
}

/// activateDNSProxyConfig is the DNSProxyConfigIntent main.swift writes during enable-dns-proxy. The
/// providerBundleIdentifier MUST be the network extension's id (the DNS proxy provider is registered as
/// part of that target's bundle). disable-dns-proxy flips just the isEnabled bit; the rest of the config
/// survives so a subsequent enable-dns-proxy doesn't need to re-set everything.
let activateDNSProxyConfig = DNSProxyConfigIntent(
    providerBundleIdentifier: HostAppExtensionID.networkExtension,
    localizedDescription: "Fleet EDR DNS Monitor",
    isEnabled: true
)
