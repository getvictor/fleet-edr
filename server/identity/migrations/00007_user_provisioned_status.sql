-- +goose Up
-- Widen users.status to carry a third lifecycle value, 'provisioned' (issue #509). A pre-provisioned account is one an admin stages
-- with an email + role before that person has ever signed in: it has a role binding but no credential and no identity row. Modeling the
-- staged state as an explicit, queryable status (the IAM-industry lifecycle model: Okta STAGED, Entra, AWS IAM Identity Center) keeps it
-- distinct from 'active' and 'disabled' rather than inferring it from the absence of an identity row, which would falsely flip an active
-- user back to "pending" whenever an OIDC identity is rebound or rotated. On first SSO login the OIDC provisioner adopts the row: it
-- links the identity, transitions 'provisioned' -> 'active', and keeps the pre-assigned role. Additive: existing rows keep their value.

-- +goose StatementBegin
ALTER TABLE users MODIFY status ENUM('active', 'disabled', 'provisioned') NOT NULL DEFAULT 'active';
-- +goose StatementEnd

-- +goose Down
-- Narrow the ENUM back. Any still-staged row is collapsed to 'disabled' first so the column modify does not fail on an out-of-range
-- value; a staged account has no credential or identity, so it could not authenticate under the reverted binary regardless.
-- +goose StatementBegin
UPDATE users SET status = 'disabled' WHERE status = 'provisioned';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE users MODIFY status ENUM('active', 'disabled') NOT NULL DEFAULT 'active';
-- +goose StatementEnd
