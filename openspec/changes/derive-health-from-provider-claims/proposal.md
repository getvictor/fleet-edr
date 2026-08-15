# Derive health from the provider's own claim

## Why

#677 shipped a check that contradicts a host's reported health against the telemetry that arrived, to catch a capture provider that wedges while reporting itself healthy. It could not read a per-provider claim, because the agent collapsed its provider map into a single component before posting, so it inferred one: it treated "this stream produced events in the last 7 days" as evidence the provider was in use.

That proxy carried two inaccuracies, both documented in the shipped code:

- a provider deliberately disabled **during** the reference window was reported as degraded until its last events aged out, because historical activity cannot distinguish "stopped on purpose yesterday" from "wedged yesterday";
- a fault outlasting the window stopped being reported, because the window emptied too.

The agent now publishes each provider's state as its own component (#707, the producer half of #702). Reading that claim removes the proxy, and both errors with it.

## What changes

The gate becomes the provider's own reported condition rather than the host's overall rollup, and the reference window is deleted outright: its constant, its counts, the second archive window, and the seven-day scan that fed it.

## What this deletes, and what gets better

- **The whole two-window apparatus.** The archive read now takes one `TimeRange` instead of a nested pair, and scans two hours instead of seven days.
- **Two documented inaccuracies**, replaced by a positive claim.
- **A precision problem in both directions.** The old rollup gate suppressed a genuine wedge on any host that happened to be unhealthy for an unrelated reason, and it could raise a second condition for a provider the endpoint already reported as stopped. Per-provider claims fix both.

## Why this needs no compatibility fallback

The derived check has never shipped in a release. #677, #691, and #702's producer half all sit under `[Unreleased]`; the newest tag is v0.4.0, which predates them. The agent and server ship together, so the detection debuts with the claim-based gate and there is no deployed population of agents that ever had it. Keeping a history-based fallback would preserve exactly the inaccuracies this removes, for hosts that cannot exist.

## Impact

- Affected specs: `server-host-status`
- Affected code: `server/visibility/api` + `internal/clickhouse` + `testkit`, `server/detection/internal/telemetryhealth`, `server/detection/internal/mysql`, `server/detection/api`
- The host read paths now select the stored `components` column, which they previously ignored, to read the claims. It is scanned into a row struct rather than added to any wire type.
- **Archive-order note.** This delta MODIFIES the requirement that the in-flight `detect-wedged-ne-provider` change ADDED. This version is the current one, so it must archive AFTER that change, or be reconciled by hand.
