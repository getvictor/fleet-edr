-- +goose Up
-- alert_event_payloads makes alert evidence self-contained (ADR-0015). At alert creation the full envelopes of the triggering events
-- are copied here, so the alert-detail view still resolves them after the raw events age out of the event store (which moves to
-- ClickHouse with a TTL, and whose alert_events -> events foreign key the cutover drops). Keyed by (alert_id, event_id); ON DELETE
-- CASCADE so an alert's evidence is reclaimed with the alert.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS alert_event_payloads (
    alert_id        BIGINT       NOT NULL,
    event_id        VARCHAR(255) NOT NULL,
    host_id         VARCHAR(255) NOT NULL,
    timestamp_ns    BIGINT       NOT NULL,
    ingested_at_ns  BIGINT       NOT NULL DEFAULT 0,
    event_type      VARCHAR(64)  NOT NULL,
    payload         JSON         NOT NULL,
    PRIMARY KEY (alert_id, event_id),
    CONSTRAINT fk_aep_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS alert_event_payloads;
