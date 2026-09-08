-- +goose Up
-- A transactional outbox for the audit row that accompanies a rule-content change (#886).
--
-- Both authoring services wrote their audit row AFTER the content transaction committed, and logged rather than returned a failure
-- to write it. That leaves a window in which a fleet's detections changed durably and nothing in the audit log names who did it or
-- why. The ordering was the lesser of the two available outcomes rather than an oversight: returning the error would report failure
-- for a change that had already happened, which is worse than a gap the error log names.
--
-- One transaction covering both is the actual fix, and it was not reachable because the audit store sits behind an interface the
-- identity context owns (ADR-0021), so a rules-context service cannot enlist it in rulecontent's transaction. An outbox reaches the
-- same guarantee without crossing that boundary: the entry is written HERE, in the same transaction as the content change, so it
-- commits if and only if the change does. A drain in the rules context turns it into an audit event afterwards.
--
-- The payload is OPAQUE to this context, which is what keeps the boundary intact. rulecontent stores bytes it does not interpret
-- and has no opinion about; the rules context serialises the audit event into them and is the only thing that reads them back.
-- Giving this table columns for actor, action and target would be rulecontent knowing what an audit event is, which is the
-- dependency the outbox exists to avoid.
--
-- The same shape as the webhook delivery outbox (#496), which is the repository's existing answer to "commit a side effect with the
-- transaction that caused it". Deliberately simpler than that one: there is no retry schedule or attempt counter, because the drain
-- runs immediately after the change and again on a sweep, and an entry that cannot be delivered is a database problem rather than a
-- remote endpoint being down.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS rule_content_audit_outbox (
	id         BIGINT       NOT NULL AUTO_INCREMENT,
	-- What the payload is, so a drain that meets an entry from a newer version can leave it alone rather than mis-decoding it.
	-- Not the audit action: this names the ENCODING, and the action is inside the payload where the rules context put it.
	kind       VARCHAR(64)  NOT NULL,
	payload    JSON         NOT NULL,
	created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	PRIMARY KEY (id),
	-- The drain reads oldest-first so audit rows land in the order the changes did, and deletes what it delivered. Both are
	-- covered by the primary key, so no second index earns its place on a table that is empty in the steady state.
	INDEX idx_rule_content_audit_outbox_created (created_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009). Dropping this would discard audit entries that have not been drained yet, which is the
-- opposite of what the table exists for.
