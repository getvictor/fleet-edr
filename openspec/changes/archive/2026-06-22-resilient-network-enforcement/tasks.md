# Resilient network enforcement: tasks

## 1. DNS proxy forwarding resilience (the incident fix)

- [x] `extension/edr/networkextension/DNSProxyProvider.swift`: bounded forward deadline on the UDP path (`udpForwardDeadlineSeconds = 3`; previously only the TCP path had a 30s linger and UDP waited on `receiveMessage` with no deadline). On deadline or upstream failure the flow is released (`closeReadWithError(nil)` / `closeWriteWithError(nil)`) so the client retries or rolls over instead of being pinned. A `DNSForwardCompletion` once-guard records exactly one outcome per forward whether the upstream answered, errored, or blew the deadline.
- [x] Telemetry stays strictly best-effort on the query and response paths: serialization / send failure does not affect forwarding or the fail-open close.
- [x] Forward deadline is a named constant alongside `tcpUpstreamLingerSeconds` with a comment tying it to the resolver round-trip budget.

## 2. Health watchdog with policy-aware bypass

- [x] Health accumulator `extension/edr/networkextension/DNSProxyHealth.swift`: sliding-window forward-outcome counter behind an injected clock so the decision is unit-testable without a live resolver (`DNSProxyHealthTests`, 10 cases).
- [x] Pure decision: `decide(policyActive:) -> Decision`. No policy active + sustained failure (>= `minSamples`, failure rate >= `failureRateToBypass`) -> bypass; policy active -> always claim (the rebuild path ships with the enforcement policy plane, deferred to Section 3, so we never open-bypass while enforcing).
- [x] Wire to the proxy: bypass is implemented as `handleNewFlow` returning `false`, which hands the flow to the system resolver (cleaner than toggling `NEDNSProxyManager` config from inside the extension, and the spec's intent). Restore is automatic: the time-based window ages out the failure samples, so the proxy probes again with no separate timer (the window IS the cooldown). Rebuild-not-bypass-while-enforcing is deferred with the policy plane.
- [x] One-shot transition logging: `Decision.transitioned` flips only when the verdict changes, so the proxy logs "entering bypass" / "resuming" once rather than on every flow (a per-flow log would re-create the log-flood this fix exists to prevent).

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

- [x] `extension/edr/Tests/EDRExtensionLogicTests/DNSProxyHealthTests.swift`: watchdog decision table (10 cases) via an injected clock: claim below min-samples, bypass on sustained failure, claim under the rate threshold, active-policy-never-bypasses, failures-age-out-ends-bypass, recovery after a successful probe, re-trip if still wedged, partial-window rate recompute, and the one-shot transition flag across bypass entry/exit.
- [ ] Watchdog `decide` covered by unit tests; the NE-side forward deadline + fail-open close + bypass wiring in `DNSProxyProvider.swift` are not unit-testable (NetworkExtension-only target) and are verified on the VM (next item).
- [ ] System / VM layer: on edr-dev with the proxy enabled, induce sustained upstream failure and assert DNS recovers automatically via the system-resolver bypass (no reboot), the forward deadline fires, and `dns_query` telemetry resumes after recovery. This is the regression guard for the 2026-06-20 incident. Needs a GUI re-activation of the NE (binary swap breaks `dns_query` delivery).

## 7. Follow-ups (out of scope here, tracked separately)

- [ ] Server-side network-response policy plane: blocklist + containment authoring, snapshot wire format, distribution, UI.
- [x] New ADR 0014 recording the fail-open-observation / explicit-block-enforcement / declarative-containment principle (no existing ADR covers it; not an amendment): `docs/adr/0014-inline-enforcement-failure-semantics.md` (Proposed; ratifies to Accepted when this change lands).
- [ ] Encrypted-DNS (DoH/DoT) interception coverage beyond the current TCP DNS path.
