-- +goose Up
-- Rewrite alerts.updated_by from a user-only BIGINT to the principal id (ADR-0017, #514), so a service-account alert transition is
-- attributable. The column has no foreign key (a cross-context FK into identity's principals is disallowed by ADR-0004; the pre-bounded-
-- context fk_alerts_updated_by was already dropped), so this is a type change plus a value backfill only.

-- +goose StatementBegin
ALTER TABLE alerts MODIFY COLUMN updated_by VARCHAR(40) NULL;
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE alerts SET updated_by = CONCAT('usr_', updated_by) WHERE updated_by IS NOT NULL AND updated_by <> '0';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE alerts SET updated_by = NULL WHERE updated_by = '0';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
