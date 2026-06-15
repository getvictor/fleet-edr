-- +goose Up
-- +goose StatementBegin
-- Host-token verification moved from argon2id (per-row salt) to keyed HMAC-SHA256 (a server-held pepper derived from the deployment
-- root key; see internal/keyring). The salt columns are no longer written or read, so drop them. No index referenced them, so the
-- DROP is a plain metadata change. This is a breaking change with no data migration: rows enrolled before HMAC hold a host_token_hash
-- that is not an HMAC of any presented token, so those hosts 401 on their next request and re-enroll via the revocation path (#86).
ALTER TABLE enrollments
	DROP COLUMN host_token_salt,
	DROP COLUMN previous_host_token_salt;
-- +goose StatementEnd
