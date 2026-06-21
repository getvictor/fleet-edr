# 0014. Inline network enforcement: observation fails open, enforcement is explicit and resilient

- Status: Proposed
- Date: 2026-06-21
- Deciders: getvictor

## Context

The EDR sits inline on the endpoint's data plane. The Endpoint Security extension can deny a process exec (`AUTH_EXEC`), and the network extension claims every DNS flow through an `NEDNSProxyProvider` and every socket flow through an `NEFilterDataProvider`. Being inline is the entire point of the product: an EDR exists to detect AND respond (isolate a compromised host, block a malicious domain, deny a process), which is what distinguishes it from a read-only telemetry agent such as osquery. We already enforce inline for process exec (`extension-application-control`), and network response (domain blocking, host containment) is the next enforcement surface we intend to build.

Inline enforcement carries an availability hazard that a passive collector does not have: a sensor that sits in the data path can take down the asset it is protecting. On 2026-06-20 it did. The `DNSProxyProvider`, which is on by default, became the sole resolver for the host (`handleNewFlow` returns `true` for every DNS flow, so the OS sends it nothing else), and when its upstream forwarding wedged it answered nothing. All name resolution died while raw IP connectivity stayed up; only a reboot cleared it. A controlled repro confirmed the proxy self-heals the moment a working upstream returns, so the failure was an internal wedge with no recovery path, not a network outage. The provider had no forward deadline on the UDP path and no health-driven recovery.

This forces a decision the codebase keeps making implicitly and should state once: when an inline component fails or is uncertain, does the traffic flow or stop? The naive reaction to the incident is "make the DNS proxy a passive observer so it can never break DNS," but that discards the response capability that justifies the product. The forces:

- A monitoring failure (telemetry capture, upstream forwarding) must never cost the user connectivity. This is the lesson the whole industry re-learned when a CrowdStrike Falcon sensor content update bricked roughly 8.5 million Windows hosts on 2024-07-19: a security agent in the data path must degrade gracefully, not catastrophically.
- An enforcement decision (deny this exec, block this domain, contain this host) is a deliberate security action whose failure semantics are a policy choice, not an accident. Containment that silently lifts itself on a sensor hiccup is worthless.
- A block is structurally cheaper and more robust than a forward: denying a DNS query needs no upstream and no network (you synthesize the answer locally), whereas forwarding an allowed query needs a healthy upstream. So the security function can be made to survive even when the network function degrades, which inverts the usual fragility.
- `extension-application-control` already embodies the right shape: it allows by default and denies only on an explicit BLOCK match, drives decisions from a persisted snapshot restored on restart, and keeps every decision deadline-guarded and non-blocking (a cold cert-cache lookup does not block the exec). The network path should inherit this, not reinvent it.

No existing ADR records this. ADR-0008 is scoped to Endpoint Security subscription choices and ADR-0007 to XPC peer validation. So this is a fresh, cross-cutting decision rather than an amendment.

## Decision

The EDR remains a deliberate inline enforcement point. Its inline components obey one failure-semantics contract, applied uniformly to process, DNS, and network flows:

1. **Observation fails open.** Telemetry capture and upstream-forwarding health are independent from the user's connectivity. A capture failure, a parse failure, an upstream-forward failure, or an uncertain/slow enrichment on a flow that no active policy denies MUST allow the flow to proceed. Observation never gates availability.

2. **Enforcement is an explicit positive decision.** A flow is denied only on an explicit match against active policy (a BLOCK rule, a domain blocklist entry, a containment ruleset). Absence of policy, a degraded sensor, or a missing attribute defaults to allow.

3. **Blocks are enforced locally, independent of network health.** A denial is synthesized on device (an `AUTH_EXEC` deny verdict; a local `NXDOMAIN` or sinkhole answer) without depending on an upstream or the forwarding path, so enforcement survives a degraded sensor that can no longer forward allowed traffic.

4. **Every inline decision is bounded, and the path self-heals.** Every synchronous decision and every upstream forward carries a deadline and a defined outcome on expiry; nothing pins a flow indefinitely. A monitoring-path wedge MUST recover without a reboot: when no enforcement policy is active the component may bypass itself (return the function to the OS, for example handing DNS back to the system resolver) and retry; when an enforcement policy is active it rebuilds rather than open-bypasses, so containment and blocks are never silently dropped. Containment state is declarative, persisted, re-applied on restart, and always preserves a management lifeline to the EDR server so an operator can lift it.

## Consequences

**Good:**

- One auditable rule for "does traffic flow when the sensor is unhappy," consistent across process, DNS, and network. New enforcement surfaces inherit the contract instead of re-deciding ad hoc.
- The 2026-06-20 class of outage cannot recur from a monitoring wedge: clauses 1 and 4 require fail-open and self-heal when nothing is being enforced.
- Containment is trustworthy: clauses 2, 3, and 4 keep a block or an isolation enforced even when forwarding is degraded or the provider restarts, matching how mature EDRs implement host isolation.
- Aligns with the platform's intended model. On modern macOS, `NEDNSProxyProvider` and `NEFilterDataProvider` are the sanctioned enforcement points (no kernel kext), so the work is making the userspace path robust, which is exactly what this contract specifies.

**Bad:**

- During a fail-open or bypass window the EDR has reduced network visibility and reduced enforcement coverage for non-policy flows. We trade security coverage for availability when nothing is actively being enforced. That is the correct trade for a monitoring tap, but it is a real coverage gap, and it must be observable (logged, ideally surfaced server-side) rather than silent.
- Clause 4's "rebuild, do not open-bypass while enforcing" means a wedged provider with an active containment policy can degrade _allowed_ traffic for the contained host while it rebuilds. We deliberately favor keeping containment intact over restoring the contained host's general connectivity. For a host under containment that is the right priority, but it is a deliberate availability cost.
- DNS-layer blocking is necessary but not sufficient: it is evaded by hardcoded IPs, `/etc/hosts`, and apps doing their own encrypted DNS (DoH/DoT) to a non-proxied resolver. This ADR therefore places real containment at the flow/content-filter layer and treats DNS blocking as a high-signal but bypassable layer. We must never present DNS blocking alone as containment.
- The contract adds engineering surface (deadlines, a health watchdog, persisted containment state) that did not exist for a pure tap.

## Alternatives considered

**Make the DNS proxy (and network path) a passive observer.** Stop claiming flows for enforcement, collect telemetry out of band, and never be able to break DNS. Attractive because it removes the availability hazard entirely and is how some EDRs collect DNS. Rejected because it discards response: no domain blocking, no host containment, no inline denial. That is the osquery model, and choosing it would contradict the product thesis (ADR-0003: this is a standalone EDR, not a passive agent). The hazard is real but it is addressed by the failure-semantics contract, not by surrendering the capability.

**Fail closed on sensor failure (deny when the sensor cannot decide).** Attractive for a maximum-security posture: never let an unobserved or unenforced flow through. Rejected as a default because it is precisely the failure mode that caused the incident and the CrowdStrike 2024 outage: a sensor bug becomes a total outage. Fail-closed remains available as a deliberate, policy-scoped choice (a containment kill-switch is exactly fail-closed for one host), but it is never the accidental behavior of a healthy-but-confused sensor.

**Enforce blocking only at the DNS layer.** Simpler: one chokepoint, the proxy returns NXDOMAIN for bad domains. Rejected as the enforcement primitive because DNS blocking is trivially bypassed (literal IPs, alternate resolvers, DoH). DNS blocking stays as a signal-rich layer; the authoritative enforcement for containment is flow-level content-filter rules.

**Do nothing architectural; just add a UDP timeout to the proxy.** The minimal fix for the incident. Rejected as insufficient on its own: a timeout stops the indefinite hang but does not give self-heal, does not define enforcement-vs-observation failure behavior, and leaves the next enforcement surface to re-decide. The timeout is necessary and is part of the implementing change, but the principle is what stops this being relitigated per surface.

## References

- Incident and analysis: `docs/dns-monitoring.md` (DNS resolution troubleshooting runbook), `extension/edr/networkextension/DNSProxyProvider.swift`, and the 2026-06-20 capture (974 `Upstream UDP connection failed` errors, ping-works/resolve-fails, reboot-only recovery).
- In-flight change this ADR governs: `openspec/changes/resilient-network-enforcement/` (capabilities `endpoint-event-collection`, `extension-network-response`, `host-app-extension-manager`). This ADR is ratified to Accepted when that change lands.
- Existing inline enforcement precedent: `openspec/specs/extension-application-control/spec.md` (allow-by-default, deny on explicit BLOCK match, persisted snapshot restored on restart, deadline-guarded non-blocking decisions). ADR-0003 (standalone EDR, not a passive agent), ADR-0008 (selective ESF subscription), ADR-0007 (XPC peer validation).
- Vendor prior art for containment with a preserved management lifeline (vendor product docs may require authentication):
  - CrowdStrike Falcon "Network Containment": isolates a host from the network while preserving connectivity to the CrowdStrike cloud so an analyst can release it. CrowdStrike product documentation, falcon.crowdstrike.com.
  - Microsoft Defender for Endpoint "Isolate device": isolation keeps the device connected to the Defender for Endpoint service. Microsoft Learn, "Take response actions on a device" (`learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts`).
  - SentinelOne "Disconnect from Network": network quarantine that maintains connectivity to the management console. SentinelOne product documentation.
- Vendor prior art for DNS-layer blocking by local answer / sinkhole:
  - Cisco Umbrella (DNS-layer security and sinkholing), `docs.umbrella.com`.
  - DNS Response Policy Zones (RPZ), Vixie and Schryver: the standard mechanism for DNS firewalling via locally synthesized answers (IETF draft `draft-vixie-dnsop-dns-rpz`; ISC documentation).
- Availability lesson: CrowdStrike "Channel File 291" external root-cause analysis of the 2024-07-19 Falcon sensor outage (~8.5 million Windows hosts), crowdstrike.com.
- Security-engineering principle: Saltzer and Schroeder, "The Protection of Information in Computer Systems" (1975), fail-safe defaults (`web.mit.edu/Saltzer/www/publications/protection/`). Note the nuance: fail-safe-defaults is default-deny for access-control _decisions_, which is clause 2 here; it does not argue for failing a _monitoring sensor_ closed, which is clause 1.
- Apple platform model: `NEDNSProxyProvider` (`developer.apple.com/documentation/networkextension/nednsproxyprovider`) and `NEFilterDataProvider` (`developer.apple.com/documentation/networkextension/nefilterdataprovider`).
