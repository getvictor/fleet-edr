# 0020. Agent updates ride the deployment channel, for now

- Status: Accepted
- Date: 2026-08-21
- Deciders: getvictor

## Context

Today an agent is upgraded by pushing a new signed `.pkg` through whatever deployment channel the customer already runs: Fleet, Jamf, Kandji, Intune, or a hand-run installer (`docs/mdm-deployment.md`). There is no in-product update mechanism, and no code for one: no Sparkle, no manifest fetcher, no updater daemon.

Two artefacts in this repo disagreed about whether that is a decision or a gap. `docs/best-practices.md` listed an in-product auto-update channel as **"will not do"**, reasoning that enterprise endpoint software updates flow through the customer's MDM and that in-product self-update bypasses change management. Issue #88, open and unresolved, argues the opposite: that the gap is significant for a top-tier EDR, citing a real incident (the edr-dev VM ran a pre-API-rename agent for weeks with no signal until a binary was copied by hand), the CVE exposure window on the agent's own parse path, and the SOC 2 / PCI-DSS expectation that endpoints demonstrably run a supported agent version.

Issue #88 is closer to right, and the "will not do" framing does not survive contact with the market. CrowdStrike, SentinelOne, and Microsoft Defender for Endpoint all ship sensor auto-update: not consumer-style self-update, but **vendor-managed updates gated by operator policy in the management console**, with version pinning (N-1 / N-2), staged rollout rings, and maintenance windows. Change management is satisfied because the console _is_ the change-management surface. Rejecting Sparkle is correct and beside the point; Sparkle is a consumer-app pattern nobody proposed. CrowdStrike's 2024 outage is the standard cautionary tale here, and it is an argument about _how_ to roll updates (rings, canaries, operator control) rather than _whether_ to.

What makes the gap survivable for us specifically, and it is a genuine structural difference rather than a rationalisation: **our detection runs server-side.** All rules under `server/rules/internal/catalog/` are compiled into the server and evaluated against uploaded events. For a sensor-resident detection engine, a stale sensor is stale detection, which is why those vendors _must_ auto-update. For us the agent is a collector, and the content that has to move fast moves when the server is deployed. The one enforcement path that does live on the endpoint, Application Control, already has a versioned push channel (`set_application_control` carrying `policy_version`), so the endpoint-content problem is solved where it actually exists.

That leaves agent updates covering agent bug fixes, ESF and OS-compatibility changes, new event types, and security fixes in the agent itself. Real, but not "detection is rotting".

## Decision

For the current pilot phase (macOS, 10 to 500 endpoints, MDM-deployed) the agent ships **no in-product update channel**, and upgrades ride the customer's deployment channel.

This is a scope decision, **not** an architectural principle, and it is explicitly expected to be revisited. Issue #88 remains open as the tracking issue and must not be closed as "won't do". `docs/best-practices.md` is corrected from "will not do" to deferred, pointing here.

Revisit when any of the following becomes true:

1. **We sell into any segment without MDM** (self-serve, small teams, or the quickstart-compose path). There, "the customer's MDM owns updates" is simply false, and agents rot at whatever version they were installed at.
2. **Detection or enforcement moves onto the endpoint** beyond Application Control, making agent version equal to detection content.
3. **Fleet-wide version skew causes an incident or costs a deal**, which is the empirical version of the same question.
4. **A security fix lands in the agent** that we need deployed faster than a customer's change window allows.

## Consequences

**Easier now.** No signing-and-distribution infrastructure to build or defend: no update server, no manifest format, no rollback story, no staged-rollout controller, and no new privileged self-replacing code path on the endpoint. That last one matters more than it sounds for a product whose own threat model treats tamper-resistance as a feature; an updater is a privileged write primitive pointed at our own binary, and it is exactly the component an attacker would rather subvert than fight.

**Worse now, and we should be honest that customers will notice.** Fleets drift, and while the drift is not invisible it is not aggregated either. Per-host visibility is fine: the agent reports `agent_version` on every status check-in, the server refreshes it through `UpdateInventory`, and host detail renders it (`HostHeader.tsx`). What does not exist is any fleet-wide view. There is no version column or filter in the host list and no distribution summary, so "which of my endpoints are on an unsupported version" remains a database query rather than a screen. An agent-side CVE then takes a release plus a per-customer deployment cycle to reach endpoints, with no in-product way to watch that rollout land. And this is a standard procurement question, so it will be asked in evaluations against the vendors named above, where the honest answer is "your MDM does it".

**Cheap to reverse, which is the point of deferring rather than refusing.** Three of the primitives an operator-policy update channel needs already exist: a bidirectional control channel to the agent (ADR-0016), a versioned content-push pattern that works in production (`set_application_control`), and per-host `agent_version` already reported on every check-in and stored server-side. What is missing is the update-policy model (rings, pinning, maintenance windows), the signed-artifact delivery path, and the fleet-wide version view that would let an operator watch a rollout, which is roughly the scope #88 already sketches.

## Alternatives considered

**Ship Sparkle or an equivalent appcast fetcher.** Rejected, and this one really is a "will not do". It is a consumer-application pattern: the endpoint polls a vendor URL and updates itself outside any operator policy. For enterprise endpoint software that genuinely does bypass change management, and it hands an attacker a self-replacing privileged code path keyed off a URL.

**Build the full operator-policy update channel now** (rings, pinning, windows, signed manifests, rollback). This is the right long-term answer and what the revisit triggers point at. Rejected for the pilot phase on sequencing: it is a substantial subsystem with its own security surface, and it buys least at the exact fleet size where an operator can push a `.pkg` through the MDM they already run. Building it before we have a customer whose MDM assumption fails means designing the policy model against a guess.

**Close #88 as "won't do" and keep the best-practices line.** Rejected. It states a permanent architectural position on what is really a phase-scoped trade-off, and it would bury a known competitive gap behind a checkbox, which is how a decision stops being revisited when its premise expires.
