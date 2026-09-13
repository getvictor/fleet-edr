-- +goose Up
-- Group to role mapping for SSO sign-in (issue #136). groups_claim names the ID-token claim that lists the operator's IdP groups; empty
-- turns the mapping off, which is how every existing row reads after this migration. group_roles is the admin-configured list of
-- {"group": ..., "role": ...} pairs, kept in the order the admin entered them so the settings page shows them back that way; NULL means
-- no pairs. The admin API validates both before writing, so a row never carries a claim without pairs or a role outside the mappable set.

-- +goose StatementBegin
ALTER TABLE oidc_config
	ADD COLUMN groups_claim VARCHAR(255) NOT NULL DEFAULT '' AFTER default_role,
	ADD COLUMN group_roles  JSON         NULL                AFTER groups_claim;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oidc_config DROP COLUMN group_roles, DROP COLUMN groups_claim;
-- +goose StatementEnd
