import Foundation

/// DNSForwardPolicy decides HOW the DNS proxy forwards a claimed flow, so the proxy can never end up inside the
/// resolution path that its own forward depends on.
///
/// The deadlock (issue #656). `NWConnection` with default parameters follows the system default route. When another
/// network extension owns that route, our forward of that provider's own resolver query goes back into its tunnel. The
/// provider cannot answer until we forward; our forward depends on the provider. The two deadlock and all host name
/// resolution stops. Measured on 2026-07-27 with Tailscale owning the default route: 730 claimed flows attributed to
/// `io.tailscale.ipn.macos.network-extension`, and host DNS dead for 11 minutes.
///
/// Why this is a FORWARDING policy and not a claiming policy. The obvious fix, and the one the issue asks for, is to
/// decline those flows so the OS resolves them without us. That does not work: returning `false` from `handleNewFlow`
/// does NOT hand the flow back to the system. Measured on edr-dev with a build that declined every flow, nothing on the
/// host could resolve at all: `dig` against either configured resolver returned no answer, `dscacheutil` returned zero
/// addresses, and `ping` could not resolve a name, while the identical queries all succeeded the moment the DNS proxy
/// configuration was disabled outright. Declining fails CLOSED. The same measurement explains the incident record, where
/// the fail-open watchdog fired 18 times, host DNS recovered in none of those windows, and only disabling the proxy
/// configuration restored it.
///
/// So a claimed flow must stay claimed and be forwarded on a path that cannot loop. Two routings express that: an
/// ordinary flow honours whatever interface the client bound, and a flow that came from another network-extension
/// provider is kept off tunnel interfaces entirely.
///
/// Pure Foundation, no NetworkExtension and no Security import, so the decision is unit-testable without a live flow.
/// The entitlement lookup is injected exactly as `DNSProxyHealth` injects its clock; the SecCode implementation and its
/// cache live in `NetworkExtensionProviderLookup`.
struct DNSForwardPolicy {
    /// How a claimed flow's upstream forward should be routed.
    enum Routing: Equatable {
        /// Ordinary flow. Pin the forward to the interface the client bound, when it bound one, so the forward cannot be
        /// silently re-routed onto a path the client did not choose. An unbound flow keeps default routing.
        case honourBoundInterface
        /// The flow came from another network-extension provider. Keep the forward off tunnel interfaces, so it can
        /// never re-enter the tunnel of a provider that may be blocked waiting on our answer. Deliberately does NOT pin
        /// to the flow's bound interface: that interface may itself BE the tunnel we must avoid.
        case avoidTunnelEgress
    }

    /// Code-signing identifier of this extension. Flows attributed to us take ordinary routing, and skip the entitlement
    /// probe: the system already keeps our own outbound connections out of the proxy chain, so there is no loop to break,
    /// and our provider holds the very entitlement the probe tests for.
    ///
    /// May be empty if the caller could not determine it (`Bundle.main.bundleIdentifier` is documented to be present for a
    /// system extension, but a misconfigured bundle can leave it nil). An empty value matches NOTHING rather than matching
    /// every unattributed flow: see `routing`.
    let ownSigningIdentifier: String

    /// routing chooses how to forward this flow. `sourceIsNetworkExtensionProvider` is the injected entitlement probe:
    /// true when the flow's source process holds `com.apple.developer.networking.networkextension`. It is an autoclosure
    /// so the SecCode walk is skipped for our own flows, keeping the common path to one string comparison.
    ///
    /// The `isEmpty` guard is load-bearing. A flow can arrive with an empty `sourceAppSigningIdentifier`, and if our own
    /// identifier were also empty the two would compare equal, silently skipping the probe and granting tunnel egress to
    /// exactly the unattributed flows least able to justify it. An empty own identifier therefore never matches, so every
    /// flow is decided by the probe instead.
    func routing(sourceSigningIdentifier: String,
                 sourceIsNetworkExtensionProvider: @autoclosure () -> Bool) -> Routing {
        if !ownSigningIdentifier.isEmpty, sourceSigningIdentifier == ownSigningIdentifier {
            return .honourBoundInterface
        }
        return sourceIsNetworkExtensionProvider() ? .avoidTunnelEgress : .honourBoundInterface
    }
}

extension DNSForwardPolicy.Routing {
    /// Whether a forward outcome on this routing may feed the health watchdog.
    ///
    /// It must not for `avoidTunnelEgress`. Those forwards are deliberately denied the tunnel, so on a host whose only
    /// route is a full tunnel they fail by construction. Counting them would drive the watchdog's failure rate toward a
    /// bypass, and a bypass is a host-wide DNS outage rather than the fail-open it is named for. One provider's queries
    /// failing is a far smaller harm than taking the whole host's resolution down, so those outcomes stay out of the
    /// accounting.
    var feedsHealthWatchdog: Bool {
        self == .honourBoundInterface
    }
}
