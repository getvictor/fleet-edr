-- +goose Up
-- event_queue is the visibility context's durable work queue (ADR-0015): the EventLog seam that decouples ingestion from detection
-- processing. It carries the full event envelope (payload included) so a claimer can build the process graph and evaluate rules
-- without a second store read. `processed` is the claim state machine: 0 unclaimed, 2 claimed/in-flight, 1 acknowledged. The
-- (processed, host_id, timestamp_ns) index backs the FOR UPDATE SKIP LOCKED claim ordered per host (ADR-0011). Rows are append-only
-- here; the high-volume retained archive lives in ClickHouse, so this table holds only the in-flight + recently-acked working set.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS event_queue (
    event_id        VARCHAR(255) PRIMARY KEY,
    host_id         VARCHAR(255) NOT NULL,
    timestamp_ns    BIGINT       NOT NULL,
    ingested_at_ns  BIGINT       NOT NULL DEFAULT 0,
    event_type      VARCHAR(64)  NOT NULL,
    payload         JSON         NOT NULL,
    processed       TINYINT(1)   NOT NULL DEFAULT 0,
    claimed_at_ns   BIGINT       NOT NULL DEFAULT 0,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_queue_claim (processed, host_id, timestamp_ns)
);
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS event_queue;
