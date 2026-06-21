# Resilient network enforcement: tasks

## 1. DNS proxy forwarding resilience (the incident fix)

- [ ] `extension/edr/networkextension/DNSProxyProvider.swift`: add a bounded forward deadline to the UDP path (today only the TCP path has a 30s linger; UDP waits on `receiveMessage` with no deadline). On deadline or upstream failure for a non-blocked query, close the flow cleanly (`closeReadWithError(nil)` / `closeWriteWithError(nil)`) so the client can retry or roll over, instead of leaving it pinned.
- [ ] Keep telemetry strictly best-effort on both the query and response paths: a serialization or send failure MUST NOT affect forwarding or the fail-open close.
- [ ] Make the forward deadline a named constant alongside `tcpUpstreamLingerSeconds`, with a comment tying it to the resolver round-trip budget.

## 2. Health watchdog with policy-aware bypass

- [ ] Add a health accumulator in the network extension that records upstream-forward outcomes over a sliding window (success / failure / timeout), behind an injectable seam so the decision logic is unit-testable without a live resolver.
- [ ] Pure decision function: given (failure rate over window, enforcement-policy-active bool), return one of {keep, bypass-to-system-resolver, rebuild-proxy}. No policy active + sustained failure -> bypass; policy active + sustained failure -> rebuild (never open-bypass).
- [ ] Wire the decision to the proxy lifecycle: bypass flips the DNS proxy off (system resolver takes over) and schedules a periodic restore attempt; rebuild tears down and re-establishes proxy connections without bypassing.
- [ ] Emit a distinct operator-facing log line on each transition (degraded -> bypass, bypass -> restored) so the bypass window is observable.

## 3. Network-response enforcement decision surface (default-forward, deferred policy input)

- [ ] Introduce the on-device decision seam: a `BlockDecision(query) -> {forward, denyLocal(answer)}` consulted before forwarding, defaulting to `forward` when no policy is loaded (so behavior is unchanged until the policy plane lands).
- [ ] Implement local denial for a matched block: synthesize an `NXDOMAIN` (or configured sinkhole answer) with no upstream contact, and emit block telemetry.
- [ ] Host containment ruleset application: a declarative content-filter ruleset applied via `NEFilterSettings`, persisted on device and re-applied on extension start (mirror the application-control snapshot persist/restore), with a management-lifeline allowance for the EDR server endpoint. Policy input stubbed/empty in this change.

## 4. Host app: bounded DNS proxy toggle

- [ ] `extension/edr/edr/main.swift`: wrap the `loadFromPreferences` / `saveToPreferences` flow in `enable-dns-proxy` / `disable-dns-proxy` with a timeout; on timeout exit non-zero with an actionable message instead of blocking.
- [ ] `extension/edr/edr/ExtensionManagerLogic.swift`: pure helper for the timeout/outcome decision so it is unit-testable.

## 5. Spec deltas

- [x] `endpoint-event-collection` delta: MODIFIED "DNS query capture" (forward deadline + fail-open on forward failure).
- [x] `extension-network-response` delta: ADDED default-forward, local-block-without-upstream, health watchdog, declarative containment.
- [x] `host-app-extension-manager` delta: ADDED bounded DNS proxy toggle subcommands.

## 6. Tests

- [ ] `extension/edr/Tests/EDRExtensionLogicTests/`: forward-deadline outcome (timeout -> flow released), telemetry-failure-does-not-block, block decision returns local denial without upstream, watchdog decision table (no-policy+fail -> bypass; policy+fail -> rebuild), containment ruleset persist/restore, bounded-toggle timeout outcome.
- [ ] System / VM layer: on a live macOS VM with the proxy enabled, induce sustained upstream failure and assert DNS recovers automatically (no reboot), and that a contained host still reaches the server. This is the regression guard for the 2026-06-20 incident.

## 7. Follow-ups (out of scope here, tracked separately)

- [ ] Server-side network-response policy plane: blocklist + containment authoring, snapshot wire format, distribution, UI.
- [x] New ADR 0014 recording the fail-open-observation / explicit-block-enforcement / declarative-containment principle (no existing ADR covers it; not an amendment): `docs/adr/0014-inline-enforcement-failure-semantics.md` (Proposed; ratifies to Accepted when this change lands).
- [ ] Encrypted-DNS (DoH/DoT) interception coverage beyond the current TCP DNS path.
