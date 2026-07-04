# Make graph-builder batch re-processing idempotent

## Why

The detection processor nacks and re-claims a batch on a retryable evaluation miss (`rulesapi.ErrProcessNotYetMaterialized`), and a claim-lease-expiry re-offer replays a stalled or crashed worker's events (ADR-0011, issue #535), so the same fork/exec/exit/snapshot/heartbeat events are folded through the graph builder more than once. The builder was not idempotent under that replay:

- Every fork / exec-without-fork / re-exec / snapshot INSERTed a fresh row (the `processes` table had only a surrogate PK, no natural key), so a replay **duplicated** process rows. Because alert dedup keys on `process_id`, the duplicate rows also produced **duplicate alerts** (`uk_alerts_dedup` is defeated when the subject process id changes).
- A first-exec-after-fork is an in-place UPDATE; on replay the now-`exec_time_ns`-set row was re-read as a **re-exec**, fabricating a phantom generation.
- An exit closes the most-recent-live row without a fork-time bound, so a replayed exit whose original pass buffered it (exit-before-fork) closed a **later** generation of a reused PID that the preload already held.
- A heartbeat set `last_seen_ns` unconditionally, so a replayed earlier heartbeat dragged freshness **backward**.

This was surfaced by the dns_c2_beacon retry work: a nack storm re-processed batches ~10x and inflated the demo's process rows (~4932 vs ~400) and alerts (`credential_keychain_dump` fired 10x for one woven attack), which then self-inflicted the processor backlog that made the demo flake. The `engine.go` comment claiming "alert dedup makes the re-run idempotent" was false because the process row underneath was not.

## What Changes

- **Tie each process row to the event that materialized it (migration 00011).** New nullable columns `source_event_id` (the fork / exec-without-fork / re-exec / snapshot event that INSERTed the row), `exec_event_id` (the exec that applied the current image, for the case-b in-place UPDATE that creates no row), and `exit_event_id` (the observed exit that closed the row). A `UNIQUE (host_id, source_event_id)` backstops the rare concurrent lease-expiry double-insert; existing rows are left NULL and MySQL allows multiple NULLs in a unique index, so no pre-migration dedup is needed and the ALTER cannot fail on historical data.
- **The builder skips an already-applied event.** `handleFork`/`handleExec`/`handleExit` call a new `EventAlreadyApplied(host, pid, eventID)` (a `source_event_id`/`exec_event_id`/`exit_event_id` probe against the same in-memory overlay the reads use) and no-op when the event's effect is already recorded, so a replay neither duplicates a generation nor re-routes a first-exec into a re-exec.
- **An exit cannot close a future-forked process.** `UpdateProcessExit` (and the overlay) restrict the close target to `fork_time_ns <= exitTimeNs`. A no-op in single-pass ingest (a process forks before it exits); on replay it stops a buffered-then-replayed exit from closing a later generation of a reused PID.
- **Heartbeat freshness is monotonic.** `UpdateLastSeenForSnapshot` (and the overlay) advance `last_seen_ns` with `GREATEST`, so a replayed earlier heartbeat cannot regress it.
- **Unchanged:** the claim/ack/nack queue contract, the batch flush shape, the alert schema and dedup, rule match logic, and every event wire shape.

## Capabilities

### Modified Capabilities

- `server-process-graph-builder`: a new requirement that re-processing a batch is idempotent (double-apply yields the identical forest), backed by the per-row creating/exec/exit event ids, the exit fork-time bound, and monotonic freshness.

## Impact

- **Affected specs:** `server-process-graph-builder` (1 added requirement).
- **Affected code:** `server/detection/migrations/00011_processes_source_event_id.sql` (new), `server/detection/api/types.go` (three fields), `server/detection/internal/mysql/processes.go` + `processbatch.go` (event-id columns, `EventAlreadyApplied`, exit fork-time bound, monotonic last-seen, batched insert/update), `server/detection/internal/graph/builder.go` + `batch.go` (guards + overlay mirror). Enables the separate `dns_c2_beacon` retryable-flow-process fix to land without a nack-storm-driven inflation.
- **Performance:** `EventAlreadyApplied` is one indexed existence probe per fork/exec/exit (backed by `uk_processes_source_event` for the source-id term); the re-processing path that reaches it runs only on a nack or lease-expiry replay, which is rare in steady state.
- **Migration safety:** additive nullable columns plus one UNIQUE secondary index; the AUTO_INCREMENT PK is unchanged, so the events/event_queue SKIP-LOCKED claim path that the reverted surrogate-PK change (00006) deadlocked is untouched.
