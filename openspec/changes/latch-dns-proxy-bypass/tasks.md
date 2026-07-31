# Latch the DNS proxy fail-open bypass: tasks

## 1. Watchdog

- [x] `extension/edr/networkextension/DNSProxyHealth.swift`: replace the implicit "window is the cooldown" recovery with an explicit three-state machine (claiming, bypassed with a hold deadline, probing with a claim budget and its own deadline). Add `bypassHoldBase`, `bypassHoldMax`, `probeClaimBudget`, and `probeTimeout` to `Config`. Discard outcomes recorded while bypassed. Replace `Decision.transitioned` with a nullable `Decision.transition` carrying bypass entry (trip count + hold), probe start, and resume.

## 2. Call site

- [x] `extension/edr/networkextension/DNSProxyProvider.swift`: log each transition once from `handleNewFlow` with a message that distinguishes entry, probe, and resume, and update the stale header comment describing the old cooldown behaviour.

## 3. Spec

- [x] `extension-network-response` delta: MODIFIED "DNS proxy health watchdog with policy-aware bypass" adds the hold, backoff, bounded probe, inconclusive re-arm, and per-transition observability, and repeats both pre-existing scenarios verbatim.

## 4. Tests

- [x] `extension/edr/Tests/EDRExtensionLogicTests/DNSProxyHealthTests.swift`: drive the full transition sequence on the injected clock (trip, hold, probe budget, re-trip with a doubled hold, cap, healthy probe resets, inconclusive re-arm, stale outcomes during the hold are discarded). Keep the existing suite green, adjusting only for the `Decision` shape change. Scenario markers on the new subtests.

## 5. Verification

- [x] `swift test` (181 tests) and `swiftlint lint --strict` green; `xcodebuild` Debug build succeeds.
- [x] `openspec validate latch-dns-proxy-bypass --strict`; spectrace 777/777; dash + markdown lints.
- [x] Live macOS VM (edr-dev, macOS 26.3) against `task dev:server`, upstream wedged with `pf` dropping the v4 resolver's replies, 20 concurrent query workers, matched 10-minute windows on the pre-fix (1.1/10) and post-fix (1.1/11) extension:

  | measure | pre-fix | post-fix |
  |---|---|---|
  | bypass entries | 17 (every ~36s) | 5 |
  | client queries pinned 3s (`Upstream UDP forward timed out`) | 348 | 62 |
  | hold schedule | none, re-claimed every window | 30s, 60s, 120s, 240s, 300s (capped) |
  | flows claimed per restore attempt | every arriving flow | at most 5, logged |

  Latched-bypass check (109s, wedge on, no competing load): 0 new forward timeouts and 0 re-trips, so the proxy conscripted nothing while held. Recovery: the trip-5 probe found the upstream healthy and logged `DNS proxy resuming` exactly once; after clearing the wedge, system resolution returned to 16ms, no further bypass entries, and all five probe `dns_query` events reached the dev server (ClickHouse). Note the host-resolution latency during the wedge is not a clean pre/post discriminator here: the `pf` wedge also blocks the system resolver's own v4 path, so both runs show tens of seconds and the honest signal is the forward-timeout count above.
