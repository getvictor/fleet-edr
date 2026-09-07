# Keep the DNS proxy out of another resolver's dependency path

## Why

`DNSProxyProvider.handleNewFlow` claims every DNS flow on the host, including the flows of other network extensions that are themselves resolvers. It then forwards each query with default parameters, so the forward follows the system default route. When another extension owns that route, our forward goes back into that extension's own tunnel. That provider cannot answer until we forward; our forward depends on that provider. The two deadlock and all host name resolution stops.

The provider's header comment asserted that "the system excludes this extension's own outbound connections from the proxy chain, so there's no infinite loop". That is true only for our own process, and it is the assumption this bug breaks.

Measured during the 2026-07-27 incident (issue #656), with Tailscale owning the default route:

- Tailscale carried 12,593 of ~13,200 DNS queries on the host.
- We claimed 730 flows attributed to `io.tailscale.ipn.macos.network-extension` in the 18 minutes before onset.
- System-wide DNS was dead from 07:09 to 07:20. `mDNSResponder` sent 3,925 queries and received 32 responses, against 698 in the preceding 28 minutes.
- Disabling only the DNS proxy configuration restored resolution inside the same minute, with no reboot, which attributes the outage to the proxy rather than to the network.

The host had four VPN configurations installed. This is a normal end-user laptop, not an exotic setup, and a host can look healthy for days and break the moment its user connects a VPN. The fail-open watchdog latched by the preceding change bounds the blast radius of a wedge; it does not stop us from creating one.

## What changes

The obvious fix, and the one this issue asks for, is to decline those flows so the OS resolves them without us. **That does not work.** Returning `false` from `handleNewFlow` does not hand a DNS flow back to the system; it kills it. Measured on edr-dev with a build that declined every flow: `dig` against either configured resolver returned no answer, `dscacheutil` returned zero addresses, and `ping` could not resolve a name, while every one of those queries succeeded the moment the DNS proxy configuration was disabled outright. Declining fails closed.

That measurement also re-reads the incident record. The fail-open watchdog fired 18 times and host DNS recovered in none of those windows; only disabling the proxy configuration at 07:21:09 restored it. That was previously read as "the bypass windows are too short". The real reason is that bypassing never restores resolution at all.

So a claimed flow must stay claimed, and the only lever is how its forward is routed:

- **A flow from another network-extension provider is forwarded off tunnel interfaces.** `NWParameters.prohibitedInterfaceTypes = [.other]`, which is how a `utun` classifies (verified on a live host: `en0` is `.wifi`, `en7` `.wiredEthernet`, `utun6` `.other`). The forward can then never re-enter the tunnel of a provider that may be blocked waiting on our answer, while the query still resolves and still produces telemetry.
- **Provider identification is by entitlement, not by vendor.** The source process is checked for `com.apple.developer.networking.networkextension` via SecCode on the flow's audit token. A bundle-identifier allowlist would silently fail for every VPN not named in it, and the incident host had four VPN configurations installed.
- **Our own provider is carved out.** It holds the same entitlement (`content-filter-provider-systemextension`, `dns-proxy-systemextension`), and the system already keeps our outbound connections out of the proxy chain, so there is no cycle to break.
- **Every other flow is pinned to the interface the client bound**, when it bound one, so a forward cannot be silently re-routed onto a path the client did not choose. A tunnel-avoiding forward is deliberately NOT pinned, because the interface the provider bound may itself be the tunnel to avoid.
- **Tunnel-avoiding forward outcomes are excluded from the health watchdog.** They are denied the tunnel by design, so on a full-tunnel host they fail by construction; counting them would drive the watchdog toward a bypass, and a bypass is a host-wide outage.
- **A provider is logged once, not once per flow.** The incident host produced 730 such flows in 18 minutes.

The entitlement result is memoised per `(pid, pidversion)`, the same process-generation identity the flow telemetry already uses, so a recycled PID is a cache miss and cannot inherit its predecessor's verdict.

### Not in this change

- **Fixing the fail-open bypass.** The measurement above shows the bypass added by #471 and latched by #657 does not fail open; it takes host DNS down. The real fix is to tear down the proxy configuration rather than decline flows, which is a different mechanism (it needs the host app or the manager, not a per-flow verdict) and deserves its own change. This change adds no new reliance on the bypass and excludes its own forwards from feeding it.
- **Tunnel-internal resolver flows that arrive with no usable source process.** Tailscale's MagicDNS flows to `100.100.100.100:53` come from its netstack rather than a userspace socket: they log as app `a.out` with local port 0 and no `filterFlowIdentifier`, so a source-process rule cannot see them. Catching those needs a destination-shaped or "unattributable source" rule, which risks declining legitimate flows and is worth designing against observed data rather than speculation. Tracked separately.
- **Datagram-level probe budgeting**, the follow-up from the preceding change.
- Any change to the forward deadline, the watchdog thresholds, or `policyActive` semantics.

## Acceptance

- With a tunnel provider up and owning the default route, host name resolution keeps working while our DNS proxy is enabled, and the log names the provider whose forwards we are routing around.
- `dns_query` telemetry is still produced for both ordinary application lookups AND the other provider's flows, since nothing is declined.
- With no tunnel running, resolution and `dns_query` telemetry are unchanged from today.
- A forward for an ordinary bound flow leaves on the interface the flow was bound to.
- No change makes the host more likely to enter the fail-open bypass.
