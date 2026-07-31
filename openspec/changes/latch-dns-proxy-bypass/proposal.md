# Latch the DNS proxy fail-open bypass

## Why

`DNSProxyHealth` is the watchdog that stops a wedged DNS proxy from taking down all host name resolution. It does not keep the host resolving, because the bypass does not hold.

The current design is "the window IS the cooldown": while bypassing the proxy records no outcomes, so after the 30s window the failure samples age out, `computeVerdict` returns `.claim`, and the proxy resumes claiming to probe the upstream. There is no probe path in `handleNewFlow`, so "probing" means claiming **every** DNS flow that arrives, and each one is pinned for the full 3s forward deadline before it fails open. Because re-tripping needs `minSamples` outcomes first, the host oscillates: bypass for ~30s, re-claim and stall live client traffic, bypass again.

Measured during the 2026-07-27 outage (issue #657):

- 18 `DNS proxy entering bypass` transitions between 07:09:11 and 07:20:34, averaging ~40s apart.
- 405 `Upstream UDP forward timed out after 3s` in the same window: forwards burned on re-claim probes.
- Host DNS recovered in **no** bypass window. `mDNSResponder` sent 3,925 queries and received 32 responses across the whole period.
- Resolution returned only when the DNS proxy configuration was disabled outright, which is the outcome this watchdog exists to make unnecessary.

The root cause of that incident is separate (#656, the proxy claims a tunnel provider's own resolver traffic and forwards it back through that tunnel). This change is about blast radius: an upstream wedge from any cause, including causes not yet diagnosed, must cost a brief telemetry gap rather than minutes of dead DNS.

## What changes

- **The bypass latches for a hold interval.** Entering bypass arms a hold; the proxy bypasses unconditionally until the hold expires, instead of clearing as soon as the failure samples age out. Outcomes recorded during the hold (in-flight forwards that started before the trip) are discarded so a stale completion cannot influence the next decision.
- **The hold backs off.** Each consecutive failed probe doubles the hold from a 30s base to a 5m cap, so a host whose upstream stays wedged for minutes spends that time on the system resolver rather than oscillating. A probe that finds the upstream healthy resets the backoff to the base.
- **A probe conscripts a bounded number of flows.** When the hold expires the watchdog enters a probe state with a small claim budget (default 5, the same floor the failure rate already needs). Those flows are claimed and accounted; every other flow arriving during the probe is still bypassed. A probe that yields no verdict before its own deadline is inconclusive and re-arms the same hold without doubling, so an idle host is not pushed to the cap by absence of traffic.
- **The transitions are individually observable.** `Decision.transitioned` becomes `Decision.transition`, a nullable enum carrying bypass entry (with the trip count and hold length), probe start, and resume. Each is logged once by `handleNewFlow`, so a single sustained bypass reads differently from a re-trip loop in the unified log, which is exactly the distinction that was missing when triaging the incident.

The worst case per hold interval falls from every arriving flow claimed to at most the probe budget, and the interval itself grows while the upstream stays wedged. The bound is per flow, not per query: a claimed `NEAppProxyUDPFlow` can carry more than one datagram, and the provider forwards each of them, so a probe's stalled-query count is the budget multiplied by the datagrams those flows happen to carry. Bounding the stall at the datagram level would have to live in the provider's forwarding path rather than in the pure-Foundation watchdog, and is left as a follow-up.

### Not in this change

- **An active probe query issued by the provider itself.** It would cost zero client-visible stalls, but it needs an upstream endpoint (only learned from a claimed flow) and a live `NWConnection` in the decision path, which would move the logic out of the pure-Foundation type that makes it unit-testable. A bounded conscription budget gets most of the benefit at a fraction of the risk.
- **The `#656` flow-exclusion and interface-pinning fix.** Independently filed and independently fixable; this change must land regardless of what caused the wedge.
- **Any change to the 3s forward deadline, the failure-rate threshold, or the sample cap.**
- **`policyActive` behaviour.** It stays wired-but-inert (`DNSProxyProvider` passes `false`) and continues to force `.claim`. The latch state is preserved underneath, so when the enforcement plane lands and a policy clears, the watchdog resumes from the state it held rather than from a clean slate.

## Acceptance

- With the upstream wedged and steady DNS load, the proxy bypasses once and stays bypassed: over a 10-minute wedge the host's DNS success rate is comparable to the proxy being disabled, and bypass entries are a handful rather than one every ~40s.
- Probing claims no more than the probe budget of DNS flows per hold interval, and bypasses every other flow arriving while the attempt is outstanding.
- Clearing the wedge restores claiming within one hold interval, `dns_query` telemetry resumes, and `DNS proxy resuming` is logged once.
- A transient blip does not leave the proxy bypassed indefinitely: the hold is bounded and the backoff resets after a healthy probe.
- An active enforcement policy still never open-bypasses.
