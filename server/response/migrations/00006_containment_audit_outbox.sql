-- +goose Up
-- A transactional outbox for the audit row that records a host being contained or released (issue #1070).
--
-- The change wrote its audit row after its transaction committed, and logged rather than returned a failure to write it, so a failed
-- audit write or a crash between the two left a host cut off from the network with nothing recording who did it or why. The audit
-- store belongs to the identity context and cannot join this context's transaction, so the change's transaction writes an entry here
-- instead, which commits if and only if the change does, and a drain turns it into an audit row. The rules context does the same with
-- detection_config_audit_outbox (issue #1022) and rule content with rule_content_audit_outbox (issue #886), in the same encoding.
--
-- held_until withholds an entry from delivery, and nothing in this context writes a held entry: a containment change knows its whole
-- audit payload before it commits, including the id of the command queued in the same transaction (issue #1073). The column is here
-- because the shared drain reads every outbox through one query, and a table without it could not be read by that query.
--
-- No secondary index: the table is empty in the steady state, and the drain reads it by primary key order.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS containment_audit_outbox (
	id         BIGINT       NOT NULL AUTO_INCREMENT,
	kind       VARCHAR(64)  NOT NULL,
	payload    JSON         NOT NULL,
	created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	held_until TIMESTAMP(6) NULL,
	PRIMARY KEY (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009). Dropping this would discard audit entries that have not been delivered yet.
