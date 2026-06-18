-- +goose Up
-- Drop two secondary indexes on `events` that carry write + storage cost for no read benefit (issue #408). On the events table the
-- index footprint exceeds the row data (0.79 GB index vs 0.52 GB data in the Render pilot diagnostics), and these two are pure waste:
--   - idx_events_host_id (host_id) is a strict left prefix of idx_events_host_type_ingested (host_id, event_type, ingested_at_ns),
--     so any host_id-only lookup is already served by the composite. No query in the codebase filters host_id without it.
--   - idx_events_type (event_type) is matched by no query: every event-type predicate in the codebase is anchored by a leading
--     host_id (GetNetworkEventsForProcess, the FetchUnprocessed/retention paths key on processed/timestamp), so the composites cover
--     them and a standalone event_type index is never chosen by the planner.
-- Both drops are folded into one ALTER with explicit ALGORITHM=INPLACE, LOCK=NONE so the operation is a single online DDL pass: the
-- explicit clauses make MySQL fail loudly rather than silently fall back to a table-copy/locking plan, and one ALTER avoids two
-- separate metadata changes. Dropping a secondary index on InnoDB is metadata-only, so INPLACE/LOCK=NONE is always satisfiable here.

-- +goose StatementBegin
ALTER TABLE events
	DROP INDEX idx_events_host_id,
	DROP INDEX idx_events_type,
	ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd

-- +goose Down
-- Recreating the indexes is safe and lossless, so unlike the forward-only schema-rewrite migrations this Down restores the prior
-- shape. It exists for a clean local rollback during development; production rollback is restore-from-backup (ADR-0009).

-- +goose StatementBegin
CREATE INDEX idx_events_host_id ON events (host_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_events_type ON events (event_type);
-- +goose StatementEnd
