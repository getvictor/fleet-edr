-- +goose Up
-- Align the rules-context attribution columns with the unified principal model (ADR-0017, #514). These columns are already VARCHAR
-- (they stored the legacy "user:<id>" / "system" convention), so this migration rewrites existing values to principal ids and changes
-- the column default from the free-form 'system' literal to the system principal id 'sys'. Runtime writes already store principal ids
-- (usr_<id> / svc_<id>); this fixes pre-cutover rows and the seed/default path. No foreign key (cross-context, per ADR-0004).

-- Rewrite legacy values: "user:<id>" -> "usr_<id>", "system" -> "sys". Each UPDATE is scoped with a WHERE so it only touches the rows
-- that carry the legacy shape.
-- +goose StatementBegin
UPDATE detection_exclusions SET created_by = CONCAT('usr_', SUBSTRING(created_by, 6)) WHERE created_by LIKE 'user:%';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE detection_exclusions SET created_by = 'sys' WHERE created_by = 'system';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE detection_rule_settings SET updated_by = CONCAT('usr_', SUBSTRING(updated_by, 6)) WHERE updated_by LIKE 'user:%';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE detection_rule_settings SET updated_by = 'sys' WHERE updated_by = 'system';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE app_control_policies SET created_by = CONCAT('usr_', SUBSTRING(created_by, 6)) WHERE created_by LIKE 'user:%';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE app_control_policies SET created_by = 'sys' WHERE created_by = 'system';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE app_control_policies SET updated_by = CONCAT('usr_', SUBSTRING(updated_by, 6)) WHERE updated_by LIKE 'user:%';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE app_control_policies SET updated_by = 'sys' WHERE updated_by = 'system';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE app_control_rules SET created_by = CONCAT('usr_', SUBSTRING(created_by, 6)) WHERE created_by LIKE 'user:%';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE app_control_rules SET created_by = 'sys' WHERE created_by = 'system';
-- +goose StatementEnd

-- Change the column default from the free-form 'system' literal to the 'sys' principal id, so a future omitted-attribution write
-- records the system principal rather than a non-principal string.
-- +goose StatementBegin
ALTER TABLE detection_exclusions ALTER COLUMN created_by SET DEFAULT 'sys';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE detection_rule_settings ALTER COLUMN updated_by SET DEFAULT 'sys';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE app_control_policies ALTER COLUMN created_by SET DEFAULT 'sys';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE app_control_policies ALTER COLUMN updated_by SET DEFAULT 'sys';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE app_control_rules ALTER COLUMN created_by SET DEFAULT 'sys';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
