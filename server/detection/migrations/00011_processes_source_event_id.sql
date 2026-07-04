-- +goose Up
-- Make graph-builder re-processing idempotent (issue: dns_c2_beacon nack storm exposed non-idempotent process inserts). The detection
-- processor nacks and re-claims a batch on a retryable miss (ErrProcessNotYetMaterialized), and cross-replica claim-lease expiry can
-- re-offer a stalled worker's events; both replay the SAME fork/exec events through the builder. Today every fork/exec INSERTs a fresh
-- row (surrogate PK only, no natural key), so a replay duplicates process rows and, because alert dedup keys on process_id, duplicates
-- alerts. Tie each row to the event that materialized it so a replay is a no-op.
--
--   source_event_id: the event_id of the fork / exec-without-fork / re-exec / snapshot event that INSERTed this row. The builder guards
--     on it (skip Close+Insert when a row for this event already exists), and UNIQUE (host_id, source_event_id) backstops the rare
--     concurrent lease-expiry double-insert at the storage layer.
--   exec_event_id: the event_id of the exec that applied this row's current image. A first-exec-after-fork is an in-place UPDATE (no new
--     row), so a UNIQUE INSERT key can't cover it; the builder reads this to recognize "this exec already applied to this lineage" and
--     avoid the case-b -> case-c re-exec misroute on replay.
--   exit_event_id: the event_id of the observed exit that closed this row. An exit is also an in-place UPDATE that targets the
--     most-recent-live row, so a replayed exit would otherwise close a DIFFERENT (newer) generation of a reused pid; the builder reads
--     this to recognize a re-applied exit and skip it. Synthetic closes (pid_reuse, ttl_reconciliation) leave it NULL.
--
-- Both are nullable and every existing row is left NULL. MySQL treats NULLs as distinct in a UNIQUE index, so the constraint bites only
-- new rows that carry a source_event_id: no pre-migration dedup step is needed and the ALTER cannot fail on historical duplicates. This
-- adds a UNIQUE secondary index only (the AUTO_INCREMENT PK is unchanged), so it does not touch the events/event_queue SKIP LOCKED claim
-- path that the reverted surrogate-PK change (00006) deadlocked.

-- +goose StatementBegin
ALTER TABLE processes
	ADD COLUMN source_event_id VARCHAR(255) NULL,
	ADD COLUMN exec_event_id   VARCHAR(255) NULL,
	ADD COLUMN exit_event_id   VARCHAR(255) NULL,
	ADD UNIQUE KEY uk_processes_source_event (host_id, source_event_id);
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009). Dropping the columns/constraint would lose the per-row event linkage that keeps re-processing
-- idempotent on every existing row; this Down is intentionally a no-op.
