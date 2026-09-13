-- +goose Up
-- Distinguish an alert from a monitor record (issue #994). A monitor-mode match is now persisted through the alert path so an operator
-- can read it, and disposition is what keeps it out of everything that makes a row an alert: the default alert list, webhook delivery,
-- triage, and the alert retention window.
--
-- Its own column rather than a reuse of either existing candidate. status is a triage state (open, acknowledged, resolved) and a monitor
-- record has not been triaged. source says which subsystem raised the row, and a monitor record from a catalog rule is still a detection.
--
-- The dedup key gains disposition, and that is the part that matters for correctness. Without it, the first finding a rule raises after
-- being promoted to alert collides with the monitor record stored for the same subject, the ON DUPLICATE KEY path absorbs it, and no
-- alert is raised: promotion would do nothing for any finding the rule had already matched in monitor. The widened key still fits
-- InnoDB's 3072-byte limit: host_id, rule_id, and subject are 1020 bytes each at utf8mb4, and source and disposition are one byte each.
--
-- The key swap is one statement so there is no moment without a uniqueness guarantee. Existing rows all take the default 'alert', and
-- the new key only adds a column to the old one, so every row that was unique before still is and the build cannot fail on a duplicate.
--
-- Three indexes lead with disposition, because every read now filters on it and monitor records are expected to outnumber alerts several
-- times over (2,327 monitor matches against 384 alerts in a week on the dogfood host). (disposition, created_at) serves the default list,
-- newest first. (disposition, rule_id, created_at) serves one rule's monitor records, which is how an operator reaches them from the
-- rule; without it that read walks every monitor record newest first looking for the rule's, measured at 103ms for a rule with none among
-- 180,000 records against 0.17ms with it. (disposition, updated_at) replaces the retention prune's (updated_at): the alert and monitor
-- prunes each select their own disposition below their own cutoff, and an index on updated_at alone would walk the other disposition's
-- rows to find them. All three were checked with EXPLAIN at that scale.
--
-- ALGORITHM=INPLACE, LOCK=NONE is stated so the change fails loudly rather than silently taking a write lock on a table on the ingest
-- path. Adding a column rebuilds the table in place with concurrent DML allowed.
--
-- Rolling upgrade: an older replica keeps inserting rows that take the 'alert' default, which is correct for everything it writes. It
-- does not filter reads by disposition, so its alert list can show monitor records the newer replicas wrote until the cutover completes.
-- No down section, per ADR-0009.

-- +goose StatementBegin
ALTER TABLE alerts
	ADD COLUMN disposition ENUM('alert', 'monitor') NOT NULL DEFAULT 'alert',
	DROP INDEX uk_alerts_dedup,
	ADD UNIQUE KEY uk_alerts_dedup (source, disposition, host_id, rule_id, subject),
	DROP INDEX idx_alerts_updated_at,
	ADD INDEX idx_alerts_disposition_created (disposition, created_at),
	ADD INDEX idx_alerts_disposition_rule_created (disposition, rule_id, created_at),
	ADD INDEX idx_alerts_disposition_updated (disposition, updated_at),
	ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd
