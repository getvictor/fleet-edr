-- +goose Up
-- Rewrite trace_sampler_settings.updated_by from a user-only BIGINT breadcrumb to the principal id (ADR-0017, #514), so a
-- service-account update is attributable. It is intentionally NOT a foreign key (a cross-context FK into identity's principals is
-- disallowed by ADR-0004), so this is a type change plus a value backfill only.

-- +goose StatementBegin
ALTER TABLE trace_sampler_settings MODIFY COLUMN updated_by VARCHAR(40) NULL;
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE trace_sampler_settings SET updated_by = CONCAT('usr_', updated_by) WHERE updated_by IS NOT NULL AND updated_by <> '0';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE trace_sampler_settings SET updated_by = NULL WHERE updated_by = '0';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
