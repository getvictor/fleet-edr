-- +goose Up
-- A transactional outbox for the audit row that records a detection-config change (issue #1022): an exclusion created or deleted, a
-- rule setting changed, or the watched-path set replaced.
--
-- Each of those wrote its audit row after its transaction committed, and logged rather than returned a failure to write it, so a
-- failed audit write or a crash between the two left a change to what the fleet detects or collects with nothing recording who made
-- it or why. The audit store belongs to the identity context and cannot join this context's transaction, so the change's transaction
-- writes an entry here instead, which commits if and only if the change does, and a drain turns it into an audit row. Rule content
-- does the same with rule_content_audit_outbox (issue #886), in the same encoding.
--
-- held_until withholds an entry from delivery. An entry is deliverable when it is NULL or has passed. A watched-path replacement's
-- audit row also reports how many hosts the set was queued for, which is known only after the transaction commits, so its entry is
-- written held and the writer clears held_until when it adds the counts. If the writer dies first, the hold lapses and the entry is
-- delivered without the counts rather than not at all. Every other change writes its entry deliverable.
--
-- No secondary index: the table is empty in the steady state, and the drain reads it by primary key order.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS detection_config_audit_outbox (
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
