-- +goose Up
-- Add a bloom-filter data-skipping index on event_id. event_id is the LAST column of the sorting key
-- (host_id, event_type, timestamp_ns, event_id), so an event_id-only predicate (EventsByIDs, the self-contained alert-evidence read)
-- cannot use the primary index and would otherwise scan the whole table, made worse by FINAL collapsing duplicates on the fly. The
-- bloom filter lets ClickHouse skip parts/granules that cannot contain the requested ids, turning the evidence read into a pruned
-- lookup. MATERIALIZE backfills the index over any parts that predate it (a no-op on a fresh archive).

-- +goose StatementBegin
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_event_id event_id TYPE bloom_filter GRANULARITY 1;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events MATERIALIZE INDEX idx_events_event_id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE events DROP INDEX IF EXISTS idx_events_event_id;
-- +goose StatementEnd
