# Fix process uid/gid overflow wedging the detection pipeline

## Why

`processes.uid` and `processes.gid` are declared signed `INT` (max 2147483647), but macOS `uid_t`/`gid_t` are unsigned 32-bit. The `nobody` account is `4294967294` (-2 as uint32) and the unset sentinel `KAUTH_UID_NONE` is `4294967295` (-1); both overflow signed `INT`, so the process insert fails with MySQL error 1264 ("Out of range value for column 'uid'").

That failure does not just drop one event. The graph builder fails the whole batch on any per-event error, and the processor then unclaims the batch and never marks it processed, so the poison event stays the oldest unprocessed row and is re-fetched and re-failed every cycle. Detection rule evaluation runs only after the batch succeeds, so it never runs. On the prod-render pilot (issue #379) this manifested as ~56k `event processing failed` / `graph builder failure, will retry batch` warnings in 6h (~2.6 retries/sec on one poisoned batch) with no new process-graph materialization or alerts: a fleet-wide stall of the detection plane triggered by a routine macOS uid, with no self-recovery.

## What changes

- **Schema.** Widen `processes.uid` and `processes.gid` to `INT UNSIGNED` so the full `uid_t`/`gid_t` range persists. Forward-only goose migration; existing rows hold only `0..2147483647` (the signed range that ever inserted successfully), so the change is lossless.
- **Pipeline resilience.** The graph builder distinguishes a permanent (non-retryable) persistence error from a transient one. A permanent error (a data-integrity violation that recurs on every retry) drops the single offending event and lets the batch advance; only a transient fault (deadlock, lock-wait timeout, lost connection) fails the batch so the processor retries it. One unpersistable row can no longer wedge the pipeline.

### Not in this change

- A dedicated `edr.events.dropped` counter for quarantined events. The builder does not currently carry a metrics recorder; the drop is logged at WARN (`event dropped: permanent processing error`) for now, and the counter can land as a follow-up that threads a recorder through the builder.
- Any agent-side change: the agent already serializes the full uint32 uid; only the column type was too narrow.
