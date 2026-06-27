-- +goose Up
-- events is the visibility context's ClickHouse event archive (ADR-0015): the durable, append-mostly home for raw endpoint
-- telemetry, the source of truth for per-process correlation and (in v0.5.0) hunting. ReplacingMergeTree(ingested_at_ns) collapses
-- at-least-once re-deliveries that share the sorting key to the latest-ingested version, so a retried or re-queued event never
-- surfaces as a duplicate. The sorting key leads with (host_id, event_type, timestamp_ns) to serve the per-process correlation read
-- and ends with event_id so each distinct event is a distinct key. payload is the raw JSON envelope as text; pid is materialized from
-- it for the correlation filter (the native JSON type + more typed columns are a v0.5.0 hunting optimization). Native TTL ages events
-- out after the retention window, replacing the relational delete sweep.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS events (
    event_id        String,
    host_id         LowCardinality(String),
    timestamp_ns    Int64,
    ingested_at_ns  Int64,
    event_type      LowCardinality(String),
    payload         String,
    pid             Int64 MATERIALIZED JSONExtractInt(payload, 'pid'),
    ingested_date   Date  MATERIALIZED toDate(toDateTime(intDiv(ingested_at_ns, 1000000000)))
)
ENGINE = ReplacingMergeTree(ingested_at_ns)
PARTITION BY toYYYYMM(ingested_date)
ORDER BY (host_id, event_type, timestamp_ns, event_id)
TTL ingested_date + INTERVAL 30 DAY;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS events;
