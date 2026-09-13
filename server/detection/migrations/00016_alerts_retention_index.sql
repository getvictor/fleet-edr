-- +goose Up
-- Index backing the alert retention prune (issue #995), the counterpart to idx_processes_exit_time for the process prune. The runner
-- selects expired alerts in batches: a range on updated_at below the cutoff, oldest first, limited to one batch, and locked for update.
-- Without an index on updated_at that ordered range is a full scan plus filesort of the alerts table on every batch, and the FOR UPDATE
-- would lock every row it scanned rather than only the batch, contending with alert inserts for the length of the pass. The existing
-- composite indexes lead with status and source, so a range on updated_at alone cannot use them.
--
-- Keyed on updated_at, not created_at, because the prune measures an alert's age from its last triage activity: an alert an analyst
-- touched inside the window is kept even if it was raised long ago.
--
-- A secondary-index add, so InnoDB builds it online and it ships single-step under ADR-0009's tiered policy. No down section, per the same
-- ADR's forward-only rule.

-- +goose StatementBegin
CREATE INDEX idx_alerts_updated_at ON alerts (updated_at);
-- +goose StatementEnd
