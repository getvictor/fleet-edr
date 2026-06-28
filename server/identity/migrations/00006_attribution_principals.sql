-- +goose Up
-- Cut the identity-context attribution columns over from a user-only BIGINT FK to the principal id (ADR-0017, #514). Paired with the
-- store-layer threading that writes the principal id. The principals spine + its backfill landed in 00005, so every usr_<id> / svc_<id>
-- referenced here already exists. Hard cutover: the BIGINT columns are rewritten in place, not kept alongside.

-- oidc_config.updated_by: BIGINT FK users -> VARCHAR(40) FK principals, NOT NULL DEFAULT 'sys'. A pre-existing user id becomes usr_<id>;
-- a NULL or legacy 0 (the #514 / #515 interim stopgap) becomes the system principal, so the NULL-attribution case is gone for good.
-- +goose StatementBegin
ALTER TABLE oidc_config DROP FOREIGN KEY fk_oidc_config_updated_by;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE oidc_config MODIFY COLUMN updated_by VARCHAR(40) NULL;
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE oidc_config SET updated_by = CASE WHEN updated_by IS NULL OR updated_by = '0' THEN 'sys' ELSE CONCAT('usr_', updated_by) END WHERE id = 1;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE oidc_config MODIFY COLUMN updated_by VARCHAR(40) NOT NULL DEFAULT 'sys';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE oidc_config ADD CONSTRAINT fk_oidc_config_updated_by FOREIGN KEY (updated_by) REFERENCES principals(id);
-- +goose StatementEnd

-- app_config.updated_by: same rewrite as oidc_config.
-- +goose StatementBegin
ALTER TABLE app_config DROP FOREIGN KEY fk_app_config_updated_by;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE app_config MODIFY COLUMN updated_by VARCHAR(40) NULL;
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE app_config SET updated_by = CASE WHEN updated_by IS NULL OR updated_by = '0' THEN 'sys' ELSE CONCAT('usr_', updated_by) END WHERE id = 1;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE app_config MODIFY COLUMN updated_by VARCHAR(40) NOT NULL DEFAULT 'sys';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE app_config ADD CONSTRAINT fk_app_config_updated_by FOREIGN KEY (updated_by) REFERENCES principals(id);
-- +goose StatementEnd

-- service_accounts.created_by: BIGINT FK users -> VARCHAR(40) FK principals. Stays NULLABLE (an env-seeded first account has no creating
-- operator); a present creator id becomes usr_<id>.
-- +goose StatementBegin
ALTER TABLE service_accounts DROP FOREIGN KEY fk_service_accounts_created_by;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE service_accounts MODIFY COLUMN created_by VARCHAR(40) NULL;
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE service_accounts SET created_by = CONCAT('usr_', created_by) WHERE created_by IS NOT NULL AND created_by <> '0';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE service_accounts SET created_by = NULL WHERE created_by = '0';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE service_accounts ADD CONSTRAINT fk_service_accounts_created_by FOREIGN KEY (created_by) REFERENCES principals(id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
