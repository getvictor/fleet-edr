-- +goose Up
-- Materialize the artifact fields the fleet-wide hunting search filters on (issue #582): a network connection's remote_address and a
-- DNS query's query_name, extracted from the JSON payload. They join pid as the queryable columns; a fleet-wide by-IP / by-domain
-- lookup (no host_id, so the (host_id, event_type, ...) primary index cannot prune) filters on these instead of JSONExtract-scanning
-- every row. The bloom_filter skip indexes let ClickHouse skip granules that cannot contain the requested value, the same idiom
-- migration 00002 applied to event_id. MATERIALIZE backfills the columns + indexes over parts written before this migration (a no-op
-- on a fresh archive; a bounded background mutation on an existing one).

-- +goose StatementBegin
ALTER TABLE events ADD COLUMN IF NOT EXISTS remote_address String MATERIALIZED JSONExtractString(payload, 'remote_address');
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events ADD COLUMN IF NOT EXISTS query_name String MATERIALIZED JSONExtractString(payload, 'query_name');
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_remote_address remote_address TYPE bloom_filter GRANULARITY 1;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_query_name query_name TYPE bloom_filter GRANULARITY 1;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events MATERIALIZE COLUMN remote_address;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events MATERIALIZE COLUMN query_name;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events MATERIALIZE INDEX idx_events_remote_address;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events MATERIALIZE INDEX idx_events_query_name;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE events DROP INDEX IF EXISTS idx_events_remote_address;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events DROP INDEX IF EXISTS idx_events_query_name;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events DROP COLUMN IF EXISTS remote_address;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events DROP COLUMN IF EXISTS query_name;
-- +goose StatementEnd
