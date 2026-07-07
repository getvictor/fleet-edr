# Retry dns_c2_beacon evaluation when the connecting process is not yet materialized

## Why

`retry-unmaterialized-process-events` closed the concurrent-batch materialization race for subject-process rules but deliberately left `dns_c2_beacon` on the silent-skip path, recording it as accepted residual risk: that rule resolves the connecting process BEFORE its suspicion gate (the gate reads the process path), so a naive retryable miss would fire for every outbound connect whose exec the agent dropped under load, turning sustained load into batch-retry storms.

That residual risk is exactly the intermittent nightly-demo failure. With intra-replica processor concurrency (#535) and cross-replica claimers (ADR-0011), the claim boundary can split the attack's `exec` (which materializes the connecting process's row) from its later `network_connect`, and the two land in batches processed concurrently. When the connect is evaluated before the exec's batch commits the row, `resolveFlowProcess` misses, the old code returned no finding, and the connect was acked, so the (Critical) beacon alert was silently and permanently lost. The 2026-07-04 nightly source leg reproduced this: with a 60s verify window and again with a 120s window the seeder failed with `missing_rules=[dns_c2_beacon]` while the other four detection alerts fired; the identical commit passed on re-run, confirming a probabilistic race, not a regression. A longer wait cannot help because the alert never arrives once the miss occurs.

## What Changes

- **`dns_c2_beacon`'s flow-process miss becomes retryable, bounded by a tighter grace.** When `resolveFlowProcess` misses and the connect's ingest age is inside a new `flowProcessMaterializationGrace`, `evalEvent` raises `rules/api.ErrProcessNotYetMaterialized` so the engine propagates it and the processor nacks and re-evaluates the batch on the next cycle, by which time the concurrent flush has committed. Alert dedup keeps the re-run idempotent. Past the grace (or with no ingest stamp) the historical silent skip applies, so an orphaned connect whose exec was never delivered cannot hold its batch in a retry loop.
- **The flow grace is deliberately tighter than the 30s subject grace (5s).** Flow resolution runs before the suspicion gate, so it is reachable by any young outbound connect, not just a pre-filtered event. A tight window still covers the real race (the process row commits within a batch flush, so a genuine race clears on the very next tick) while capping how long a genuinely orphaned connect can nack its batch, directly bounding the storm the sibling change flagged. The grace also self-disables under backlog (events arrive older than the grace), so a stressed processor keeps pre-change behaviour.
- **Unchanged:** the claim/ack/nack queue contract, the batch flush, the alert schema and dedup, the rule's match logic and suspicion gate, and every wire shape. The grace is a compiled constant; no new configuration surface.

## Capabilities

### Modified Capabilities

- `server-detection-rules-engine`: a new requirement that a young outbound `network_connect` whose connecting process row is missing fails the batch with the retryable error class (so the processor re-evaluates it) under a grace tighter than the subject-process grace, while a connect past the grace window keeps the historical skip. This supersedes the flow-resolution carve-out and the documented residual risk in `retry-unmaterialized-process-events` (that change's delta prose is updated to match so the batched archive stays consistent).

## Impact

- **Affected specs:** `server-detection-rules-engine` (1 added requirement); `retry-unmaterialized-process-events` delta prose reworded to drop the now-superseded flow carve-out and residual-risk note.
- **Affected code:** `server/rules/internal/catalog/materialize.go` (tighter grace constant + shared `withinGrace` helper), `server/rules/internal/catalog/dns_c2_beacon.go` (retryable flow-process miss). The engine propagation (`engine.go`) and processor nack path already exist from the sibling change.
- **Performance:** the check is one integer comparison on an already-nil lookup branch; a batch retry occurs only when the race actually fires and resolves on the next poll tick, bounded by the 5s grace and self-disabled under backlog.
- **Residual risk:** a connect whose exec is genuinely never delivered still produces no alert (correct: there is no attributable process); it now costs at most a few nack/re-claim cycles within the tight grace rather than a permanent silent drop of a real beacon.
