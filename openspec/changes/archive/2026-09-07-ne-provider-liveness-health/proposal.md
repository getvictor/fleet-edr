# Report network extension health from capture-provider liveness

## Why

The agent marks the `network_extension` component healthy the moment its XPC session to the extension connects. That session proves the extension PROCESS is running. It has never proved that anything is capturing.

`extension/edr/networkextension/main.swift` starts the XPC listener BEFORE `NEProvider.startSystemExtensionMode()`, so an extension process in which no provider has started, or ever will, accepts the agent's connection and reports healthy. Observed on a dogfood host on 2026-07-17: a disable then re-enable of the network extension from System Settings relaunched the process with neither provider starting (the DNS proxy start torn down with `NEAgentErrorDomain Code=2`, the filter session ending with "configuration has been removed"), the agent reconnected, health went green, and the host produced no `network_connect` or `dns_query` events for 24 hours with no signal on any surface.

This is not a rare shape. It recurred repeatedly during this issue's own QA: every activation that half-failed left the process up, the listener bound, the agent connected, and both providers dead. The operator-visible result is a green dashboard over a host that stopped seeing network activity, which for a security product is worse than an outage that announces itself.

## What changes

- **The extension reports which capture providers are running.** `NetworkFilter` and `DNSProxyProvider` record their own start and stop, and the extension broadcasts the resulting provider-to-state map.
- **It re-broadcasts on every agent handshake.** The state is level-triggered, not an event: an agent that connects after the providers started must be told the current state rather than waiting for a transition that may never come. Buffering cannot carry it reliably either, since a busy host can evict a status message from the bounded pending buffer before the agent connects.
- **A deliberate stop is reported as absence, not as a fault.** DNS proxying is opt-in, so a host that turned it off is correctly configured, and reporting it stopped forever would train operators to ignore the signal. The platform's stop reason is what distinguishes the two: `userInitiated`, `providerDisabled`, `configurationDisabled`, `configurationRemoved`, `superceded`, `userLogout` and `userSwitch` are deliberate; everything else, including the `configurationFailed` and `providerFailed` shapes the incident produced, is a fault.
- **The agent grades health from the report rather than from connectivity.** No running provider is unhealthy (`no_providers_running`) even with a perfect XPC session; a stopped provider is unhealthy (`provider_stopped`) and named in the message; a session with no report yet is degraded (`awaiting_provider_status`) rather than healthy.
- **The report rides the existing event channel and never reaches the server.** The agent's XPC bridge only surfaces messages carrying a `data` blob, so a dedicated message kind would mean changing the C bridge, the cgo callbacks and the non-darwin stub for a payload the agent consumes locally. Instead it is a well-formed envelope with a control `event_type` that the agent recognises, applies to health, and drops before the upload queue.

Both the component and reason vocabularies are open by contract (`server/endpoint/api/status.go`), so this needs no server change.

### Not in this change

- **Detecting a provider that reports itself running while wedged.** The second manifestation in #649 was exactly that: a DNS proxy session stuck on "a pending start command already exists" while claiming state `Running`, logging nothing. Nothing inside the provider distinguishes that from an idle host, so it needs data-flow evidence (network telemetry stops while exec telemetry continues). That is server-side and belongs with the telemetry-loss alerting in #348.
- **Self-healing.** This change makes the failure visible; it does not re-activate anything. Automatic re-activation is #632, which can now key on a health signal that is actually true rather than on `never_connected`, which never fired for this shape.
- Any change to what the extension captures, to the event wire schema, or to the ESF extension's health, which keeps grading on connectivity because its provider starts with its process.

## Acceptance

- An extension process whose providers never start reports `network_extension` unhealthy, with the XPC session established.
- Stopping one provider for a fault reason reports unhealthy and names it; the other provider continuing does not mask it.
- Deliberately disabling the DNS proxy leaves the component healthy.
- A host with both providers running reports healthy, as it does today.
- No provider-status message reaches the server or the event queue.
