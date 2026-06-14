# Processes retention window

## Why

The retention runner only deletes from `events` (`EDR_RETENTION_DAYS`, default 30, hourly). The `processes` table has no retention or pruning whatsoever, so rows accumulate indefinitely (issue #360). The only process-side background job, the freshness-TTL reconciler, synthesizes a missing exit time for missed-exit rows; it never deletes. On 2026-06-13 a single dev host had accumulated 275K process rows across test sessions, and `GET /api/hosts/{host_id}/tree` tripped its 500ms slow-request warning at 1.1s because the "alive at any point in the window" predicate scanned ~158K index entries. On a long-lived pilot host the same unbounded growth would surface in production, and restore-from-backup makes it worse.

## What changes

- **Retention runner prunes completed processes.** The existing `RetentionRunner` gains a second batched DELETE, on the same cadence and `EDR_RETENTION_DAYS` cutoff as the event delete. No new config surface: pruning is on whenever event retention is on.
- **Keyed on exit time, not fork time.** A record is prunable only once it has a recorded exit time older than the cutoff. A still-running record (no exit time, which includes the live snapshot working set) is therefore never deleted, and a long-running process that only recently exited is retained for the full window measured from its exit. This is strictly safer than a fork-time predicate (it can never delete a row that is part of a live process tree) and the issue's "preserve the live snapshot working set" guard holds by construction.
- **Two-job composition.** Stale records whose exit event went missing are force-closed by the freshness-TTL reconciler (#6, default-on at 6h), which sets a synthesized exit time; they then become prunable here once that exit ages past the window. TTL marks dead, retention deletes old-dead.
- **Alert FK guard.** `alerts.process_id` is `ON DELETE RESTRICT`, so the prune skips any process referenced by an alert (`NOT EXISTS`, index-backed by InnoDB's implicit FK index) and alert detail views keep resolving their originating process.
- **Supporting index.** `idx_processes_exit_time (exit_time_ns)` turns the ordered range delete into a bounded range scan, mirroring `idx_events_timestamp` for the event delete.
- **Observability.** A dedicated counter `edr.retention.processes.rows_deleted` (separate from the event-row counter) plus span attributes.

### Not in this change

- Bounding the `/tree` query's "alive-before-window" lookback (the secondary optimization called out in #360). The new index and the bounded table make it smaller; it can land separately.
- Any new env var or per-host override; the prune reuses `EDR_RETENTION_DAYS`.
