# Tasks

## 1. Per-row event linkage (migration + schema)

- [x] 1.1 Migration 00011: add `source_event_id`, `exec_event_id`, `exit_event_id` (VARCHAR(255) NULL) to `processes` plus `UNIQUE (host_id, source_event_id)`; nullable + NULL-for-existing so no dedup step and the ALTER cannot fail on historical duplicates.
- [x] 1.2 Add `SourceEventID` / `ExecEventID` / `ExitEventID` to `api.Process`; thread through the shared insert column list/args, the batched preload SELECT, `GetProcessByPID`, `UpdateProcessExec`, `ReExec`, and the batched CASE-UPDATE column set.

## 2. Idempotency guards

- [x] 2.1 Add `EventAlreadyApplied(host, pid, eventID)` to the store and the batch overlay (probe source/exec/exit event ids).
- [x] 2.2 `handleFork`/`handleExec`/`handleExit` no-op when the event is already applied; stamp `source_event_id` on inserts, `exec_event_id` on the case-b exec UPDATE and re-exec/without-fork inserts, and `exit_event_id` on the exit close.
- [x] 2.3 Bound the exit close to `fork_time_ns <= exitTimeNs` (store + overlay) so a replayed exit cannot close a future-forked generation.
- [x] 2.4 Make `UpdateLastSeenForSnapshot` monotonic (`GREATEST` / advance-only) in store + overlay.

## 3. Tests

- [x] 3.1 Integration: double-apply == single-apply across the crafted state-machine scenarios (fork/exec-case-b/re-exec/pid-reuse/exec-without-fork/snapshot) and a property-based random-sequence variant.
- [x] 3.2 Confirm the existing differential (batched == per-event) and full graph state-machine suites still pass with migration 00011 applied.
