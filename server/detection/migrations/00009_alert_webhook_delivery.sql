-- +goose Up
-- Outbound alert webhook (#496): operator-managed destinations plus a transactional-outbox delivery table.
-- webhook_delivery rows are enqueued in the same transaction as the alert insert / status change, so a queued
-- delivery is never lost across a replica restart and is never queued when the alert itself did not persist.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS webhook_destination (
	id            BIGINT AUTO_INCREMENT PRIMARY KEY,
	name          VARCHAR(255) NOT NULL,
	url           VARCHAR(2048) NOT NULL,
	secret_sealed VARBINARY(512) NOT NULL,
	event_types   SET('alert.created', 'alert.status_changed') NOT NULL DEFAULT 'alert.created',
	min_severity  ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
	enabled       TINYINT(1) NOT NULL DEFAULT 1,
	created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	updated_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	INDEX idx_webhook_destination_enabled (enabled)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS webhook_delivery (
	id               BIGINT AUTO_INCREMENT PRIMARY KEY,
	public_id        CHAR(36) NOT NULL,
	alert_id         BIGINT NOT NULL,
	destination_id   BIGINT NOT NULL,
	event_type       VARCHAR(40) NOT NULL,
	dedup_key        VARCHAR(120) NOT NULL,
	payload          JSON NOT NULL,
	attempt          INT NOT NULL DEFAULT 0,
	status           ENUM('pending', 'delivered', 'failed') NOT NULL DEFAULT 'pending',
	next_attempt_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	last_status_code INT NULL,
	last_error       VARCHAR(1024) NULL,
	created_at       TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	updated_at       TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	UNIQUE KEY uk_webhook_delivery_public (public_id),
	UNIQUE KEY uk_webhook_delivery_event (alert_id, destination_id, dedup_key),
	INDEX idx_webhook_delivery_claim (status, next_attempt_at),
	INDEX idx_webhook_delivery_destination (destination_id),
	CONSTRAINT fk_webhook_delivery_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
	CONSTRAINT fk_webhook_delivery_destination FOREIGN KEY (destination_id) REFERENCES webhook_destination(id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS webhook_delivery;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS webhook_destination;
-- +goose StatementEnd
