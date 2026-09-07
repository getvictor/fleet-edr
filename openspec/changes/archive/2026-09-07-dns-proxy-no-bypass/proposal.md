# Stop the DNS proxy from taking host DNS down while trying to protect it

## Why

The DNS proxy's fail-open bypass does not fail open. It takes host name resolution down.

The bypass is implemented by returning `false` from `handleNewFlow`, on the premise that this hands the flow back to the system resolver. Apple documents the opposite:

> "If the proxy implementation decides to not handle the flow and instead **terminate it**, the subclass implementation of this method should return NO. ... In this case **the flow is terminated**."

There is no fallback path for a DNS proxy, because the proxy *is* the configured resolver. Measured on edr-dev with a build that declined every flow:

| client                 | every flow declined | proxy configuration disabled |
| ---------------------- | ------------------- | ---------------------------- |
| `dig` @v4 and @v6      | no answer           | resolves                     |
| Go pure-resolver probe | connection refused  | resolves                     |
| `dscacheutil`          | 0 addresses         | resolves                     |
| `ping` name resolution | fails               | resolves                     |

The incident record agrees independently: issue #657 documents the watchdog firing 18 times on a dogfood host with DNS recovering in **none** of those windows, and resolution returning only when the proxy configuration was disabled by hand. That was read at the time as "the bypass windows are too short". The real reason is that bypassing never restores resolution at all.

So the mechanism added by #471 and latched by #657 is not a safety valve. It is self-inflicted harm at exactly the moment an operator is least able to diagnose it, which is the worst category of failure for software sitting in a critical path.

## What changes

- **The bypass is deleted**, along with its latch, its backoff and its bounded probe. That machinery managed a mechanism that cannot work. A claimed flow now stays claimed.
- **A failing upstream is answered by trying another resolver, not by leaving the path.** The resolver list is read from the dynamic store (`State:/Network/Global/DNS`), the source `scutil --dns` reads; `NEDNSProxyProvider.systemDNSSettings` returns nil inside a running provider and cannot be used. When the resolver the client addressed is part of the system DNS configuration, a failed forward is retried against a different resolver from that configuration, which is exactly what `mDNSResponder` does when it rotates across them. The answer is returned to the client as though it came from the resolver it originally addressed, or the client would discard a reply from an address it never queried.
- **A client-chosen resolver is never substituted.** `dig @8.8.8.8`, a container's own resolver, or a split-horizon corporate server reached deliberately gets no failover: split-horizon zones resolve differently per resolver, so a "helpful" retry could hand back a wrong address for an internal name. A failed lookup is the correct outcome and matches what the client would get without the proxy in the path.
- **The per-attempt deadline drops from 3s to 1.5s.** With at most one failover attempt the worst case a client can experience stays at the same 3s a single attempt used to cost, while a query the first resolver will not answer gains a real second chance. A typical resolver answers in well under 100ms, so 1.5s is ample; 3s was chosen as "past a sane round-trip" and is over-conservative by more than an order of magnitude.
- **The health accounting survives as a reporter.** It still measures the recent failure rate and now reports degradation and recovery once per change, but nothing it says changes whether a flow is claimed.

### Not in this change

- **Surfacing forwarding degradation to agent health.** The signal is currently a log line. Routing it into the agent's health registry belongs with issue #649, which owns network-extension health reporting and is where the plumbing (a provider-to-agent status channel) has to live anyway.
- **A last-resort exit from the DNS path.** `cancelProxyWithError` is the documented API for "a network error that renders the proxy no longer viable" and is the only candidate that removes us from the path without writing NE configuration. Its semantics on macOS (does the system restart the provider, does the content filter in the same process survive) are not yet measured, so it is not being built on speculation.
- **Programmatic teardown of the DNS proxy configuration.** Deliberately rejected rather than deferred: NE preference saves can fail `permission denied`, observed on edr-dev leaving both providers dead with no headless way back. Automatic recovery built on that would convert a DNS outage into permanent silent telemetry loss, which is the failure class of #632 and #649.
- Any change to the forward-failure telemetry contract, the routing decisions from #656, or `policyActive` semantics.

## Acceptance

- No code path returns `false` from `handleNewFlow` as a recovery action.
- With one system resolver unreachable and another reachable, queries that used the system configuration still resolve, and `dns_query` telemetry is still produced.
- A query aimed at a resolver outside the system configuration is not redirected to a different one.
- The worst-case client wait across all attempts does not exceed what a single pre-change attempt cost.
- Sustained forwarding failure is reported once as degraded and once again on recovery, and the host keeps resolving names throughout via the failover path where one exists.
