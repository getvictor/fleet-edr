-- +goose Up
-- Durable per-rule monitor-match counts (issue #813). A rule in monitor mode evaluates and records instead of alerting, and until
-- now the only trace of a match was an OTel counter and a DEBUG log: an operator deciding whether to promote a rule had nothing in
-- the product to decide against. This is that record.
--
-- Rows are (rule_id, host_id, day) so a reader can ask both questions a promotion turns on: how often does this fire (SUM over a
-- window) and how widely (COUNT(DISTINCT host_id)). Those are different decisions. A rule matching thousands of times on one host
-- wants an exclusion; the same volume spread over the whole fleet means the rule itself is too broad. Collapsing to a fleet total
-- would answer only the first half.
--
-- Day granularity rather than a raw row per match: a monitor rule can match commonplace commands on every host, and the promotion
-- decision needs a rate, not a log. It also bounds the table by (rules that matched) x (hosts they matched on) x (retained days)
-- rather than by event volume.
--
-- No foreign keys. rule_id names a rule in the in-memory catalog, not a table, and host_id belongs to the endpoint context
-- (ADR-0004 forbids the cross-context FK). A row for a rule or host that no longer exists is harmless and ages out.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS detection_rule_match_counts (
	rule_id     VARCHAR(64)  NOT NULL,
	host_id     VARCHAR(255) NOT NULL,
	-- The UTC day the matches fell on. DATE (not DATETIME) because the column IS the bucket, and a reader aggregating a window
	-- compares whole days.
	day         DATE         NOT NULL,
	match_count BIGINT       NOT NULL DEFAULT 0,
	first_seen  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	last_seen   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	-- (rule_id, day, host_id) rather than (rule_id, host_id, day): the leftmost prefix (rule_id, day) serves the per-rule window
	-- aggregate, which is the read this table exists for, and the full key still gives the upsert its unique target.
	PRIMARY KEY (rule_id, day, host_id),
	-- The prune sweep deletes by age across every rule, so it needs a day-leading index of its own.
	INDEX idx_detection_rule_match_counts_day (day)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS detection_rule_match_counts;
-- +goose StatementEnd
