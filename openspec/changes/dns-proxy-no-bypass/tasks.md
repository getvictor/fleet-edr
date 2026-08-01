# Stop the DNS proxy from taking host DNS down while trying to protect it: tasks

## 1. Delete the bypass

- [x] `extension/edr/networkextension/DNSProxyHealth.swift`: reduce the watchdog to a degradation reporter. Remove `Verdict`, `Decision`, `Transition`, the bypass hold, the exponential backoff, the bounded probe and their configuration. `record(ok:)` now returns the new `Status` only when it differs from the last reported one, so a change is logged once rather than per forward.
- [x] `extension/edr/networkextension/DNSProxyProvider.swift`: remove the bypass branch from `handleNewFlow` entirely, and delete the transition-logging extension that existed only to narrate it.

## 2. Retry another resolver instead of leaving the path

- [x] `extension/edr/networkextension/DNSUpstreamFailover.swift`: new pure-Foundation rule choosing the next system resolver after a failure, and refusing to substitute when the client addressed a resolver outside the system configuration. Also renders an endpoint's address for comparison, stripping the interface scope from a link-local (`fe80::1%en0`) because the system configuration lists these unscoped.
- [x] The resolver list comes from `SCDynamicStore` (`State:/Network/Global/DNS`), the same source `scutil --dns` reads, NOT from `NEDNSProxyProvider.systemDNSSettings`. The latter is the obvious candidate and does not work: measured on edr-dev (macOS 26.3) inside a running provider it returns **nil** while the host genuinely had two resolvers configured, so a failover built on it can never fire. That is worse than no failover, because the spec would assert a safety property that never happens. Caught by live QA after the first implementation shipped exactly that dead path.
- [x] `extension/edr/networkextension/DNSProxyProvider.swift`: bundle a forward attempt into `UDPForwardRequest` (carrying `target` separately from `replyEndpoint` so a failover answer is still returned as though it came from the resolver the client addressed); retry once on failure; emit `dns_query` telemetry once per datagram in the read loop rather than per attempt, so a failover cannot double-emit.

## 3. Bound the client wait

- [x] `extension/edr/networkextension/DNSProxyTypes.swift`: per-attempt deadline 3s to 1.5s, so two attempts cost the same worst case a single attempt used to.

## 4. Report rather than act

- [x] `extension/edr/networkextension/DNSProxyProvider.swift`: `recordForwardOutcome` accounts only the final outcome of a query (a query rescued by the failover is not a failure), skips tunnel-avoiding forwards for the reason #656 established, and logs degraded/recovered once per change.

## 5. Spec

- [x] `extension-network-response` delta: REMOVED "DNS proxy health watchdog with policy-aware bypass" with the reason and migration; ADDED "DNS proxy reports forwarding degradation without leaving the DNS path".
- [x] `endpoint-event-collection` needs no change: its forwarding-resilience requirement already defers health-driven recovery to the network-response capability, which is where the replacement requirement lives, and its per-query "bounded by a deadline, release the flow cleanly" contract still holds.

**Archive ordering hazard.** `openspec/changes/latch-dns-proxy-bypass/` is merged but not archived and MODIFIES the same requirement this change REMOVES. At release, archive `latch-dns-proxy-bypass` BEFORE `dns-proxy-no-bypass`, or the modify will be applied to a requirement that no longer exists. This is the same-requirement delta collision recorded in the release-checklist hazards.

## 6. Tests

- [x] `DNSProxyHealthTests.swift`: rewritten for the reporter model (degradation reported once, recovery reported promptly once the window empties, occasional failures are not degradation, window expiry, sample cap, clamped `minSamples`). Every bypass/latch/backoff/probe test deleted with the behaviour.
- [x] `DNSUpstreamFailoverTests.swift`: failover to the next system resolver wherever the failed one sits in the list, no substitution for a client-chosen resolver, no failover with a single or empty system configuration, and no failover for an unrenderable target.

## 7. Verification

- [x] `swift test` (202 tests) and `xcodebuild` Debug build green.
- [x] `swiftlint lint --strict`; `openspec validate dns-proxy-no-bypass --strict`; spectrace 775/775 with the 2 removed-requirement scenarios correctly exempted; dash + markdown lints.
- [x] Live macOS VM (edr-dev, macOS 26.3). Blocking one of the two system resolvers while the other stays reachable:

  | measure                                    | before this change            | after                        |
  | ------------------------------------------ | ----------------------------- | ---------------------------- |
  | query aimed at the blocked system resolver | timed out, no answer (5022ms) | resolves in ~1.6s            |
  | failover retries / attempt timeouts        | 0 / 7                         | 8 / 8                        |
  | degraded reported                          | n/a                           | 0 (every query was rescued)  |

  The ~1.6s is the design working: 1.5s on the blocked resolver, then the failover answers. A query aimed at `8.8.8.8`, which is not in the system configuration, resolved in 22ms and was never substituted. With EVERY resolver blocked so nothing can answer, degradation was reported exactly once across 8 failing queries, and recovery exactly once after the resolvers returned, confirming the reporter fires per change rather than per forward and that only final outcomes are accounted.

  Caught by this QA and fixed before merge: the first implementation read the resolver list from `NEDNSProxyProvider.systemDNSSettings`, which returns nil inside a running provider, so the failover was dead code that could never fire (0 retries against 7 timeouts). The source is now `SCDynamicStore`.
