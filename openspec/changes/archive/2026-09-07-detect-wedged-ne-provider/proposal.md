# Detect a network-extension provider that wedges while reporting itself healthy

## Why

A macOS network-extension provider can start, report itself running, and then stop delivering events, with nothing on the endpoint able to tell that state from an idle machine (issue #677). Three distinct causes present with this identical signature:

1. A System Settings disable/re-enable that relaunches the extension process with no provider sessions.
2. A DNS proxy session that wedges, keeps claiming state `Running`, and logs nothing at all.
3. A binary swap during a redeploy, which kills flow delivery while XPC still connects.

In every one, the agent's own health is the signal that lies, so #649's provider-liveness work cannot close this: the provider DID start, so it correctly reports itself running. The server holds the other half of the contradiction, which the endpoint does not have: whether the events actually arrived.

This was not hypothetical. On the dogfood host the state lasted from 2026-07-17 15:00 to 07-19 11:20 while the console showed the host healthy throughout.

## What changes

The server derives per-host health conditions from a contradiction between two independent sources: the health snapshot the agent posted, and the telemetry that actually reached the archive. A host whose reported health claims everything is fine, whose process telemetry is still arriving, and whose flow telemetry for a stream it does use has stopped, is surfaced as degraded naming the provider to remediate.

The conditions are derived at read time on both host read paths, so the Hosts-list badge and the host page cannot disagree about the same host. They are carried in their own `derived_components` field rather than merged into the agent-reported `components`, because the whole point is that the two disagree and an operator has to be able to tell them apart.

## Thresholds, and why they are these

Measured against 30 days of the dogfood host's archive (~15M events), bucketed at 10 minutes:

| | |
| --- | --- |
| The wedge | one run, 2026-07-17 15:00 to 07-19 11:20: 227 buckets carrying process activity with zero flow events (37.8 hours' worth) across 44.3 hours of wall clock, the gaps being the machine asleep. On 07-18 alone: 134,132 process events, 0 `network_connect`, 0 `dns_query`. |
| Every other silence in the month | 30 minutes or shorter. DNS silence with connections still flowing: 21 runs, longest 30 minutes. Connection silence: 6 runs, all 10 minutes. |

Benign silence tops out at 30 minutes and the real fault ran for days: a 75x separation with nothing in between. So the silence window is **2 hours**, 4x above the worst benign run observed and still catching a wedge inside the first 5% of its life.

Two designs died on that data and are recorded so they are not re-derived:

- **A per-host flow-to-exec ratio baseline** (the issue's own suggestion) buys nothing that a plain "any process activity" gate does not already give, and costs stored history.
- **Widening the window** does not trade false positives against detection latency here the way it normally would. The two populations are disjoint, so 2 hours and 12 hours have the same false-positive count: zero.

## What this deliberately does not do

- **It does not name the provider from the agent's health claim**, because that claim does not exist on the wire. #649 collapses the per-provider liveness map into a single `network_extension` component before it leaves the agent, and provider names appear only in the message text when something is already stopped. The provider is named from the silent stream instead. Publishing the per-provider map to the server is tracked separately; it would also remove the reference-window ceiling below.
- **It does not persist the derived state**, so it is not indexable and cannot back a fleet-wide "hosts needing attention" filter. No such filter exists today; the stored `host_health.overall_status` column remains the agent-reported rollup and is what one would select on.
- **It does not cover the ESF extension going quiet.** Process events are the ESF signal, so ESF silence means no events at all, which reads as offline and is already covered. It is a genuinely separate contradiction (health running, `/api/status` still arriving, no events of any kind).
- **It does not exempt a host mid-deploy.** Swapping the extension binary produces a true positive: capture really is dead. The signal is correct, and the operator performing the swap knows why.

## Impact

- Affected specs: `server-host-status`
- Affected code: `server/visibility/api` + `internal/clickhouse` (a per-host, per-stream counting read), `server/detection/internal/telemetryhealth` (new, the pure derivation), `server/detection/internal/mysql` (both host read paths), `ui/src/components/HostHeader.tsx`
- The reference window is a proxy for "this host uses this provider", not an answer to it, and it is inaccurate in two bounded ways. A wedge outlasting 7 days empties the window too and stops being reported. A provider deliberately disabled *during* the window is reported until its last events age out, because historical activity cannot separate "stopped on purpose yesterday" from "wedged yesterday". Both disappear once the agent publishes per-provider liveness (#702); until then 7 days is chosen against the 44-hour incident on record, a 4x margin on the case that matters most, accepting the staleness as its cost.
