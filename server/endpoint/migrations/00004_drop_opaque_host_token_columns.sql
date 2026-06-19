-- +goose Up
-- +goose StatementBegin
-- The opaque-bearer-token machinery is gone: host tokens are now self-validating signed tokens verified by signature, not by a stored
-- keyed hash, and credential cycling is a token_epoch bump rather than a rotate-with-grace. Drop the columns + indexes that backed the
-- old model. The unique/prev-token indexes are dropped first because their columns are going. This is a hard cutover with no data
-- migration: in-flight opaque tokens already 401 (signature verify fails) and re-enroll.
ALTER TABLE enrollments
	DROP INDEX uk_enrollments_token_id,
	DROP INDEX idx_enrollments_prev_token,
	DROP COLUMN host_token_id,
	DROP COLUMN host_token_hash,
	DROP COLUMN host_token_issued_at,
	DROP COLUMN previous_host_token_id,
	DROP COLUMN previous_host_token_hash,
	DROP COLUMN previous_token_expires_at;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Re-add the columns as nullable (the original data is gone, so the NOT NULL constraints from 00001 cannot be restored) and recreate
-- their indexes, so a dev rollback leaves a structurally compatible table.
ALTER TABLE enrollments
	ADD COLUMN host_token_id VARBINARY(32) NULL,
	ADD COLUMN host_token_hash VARBINARY(255) NULL,
	ADD COLUMN host_token_issued_at TIMESTAMP(6) NULL,
	ADD COLUMN previous_host_token_id VARBINARY(32) NULL,
	ADD COLUMN previous_host_token_hash VARBINARY(255) NULL,
	ADD COLUMN previous_token_expires_at TIMESTAMP(6) NULL,
	ADD UNIQUE KEY uk_enrollments_token_id (host_token_id),
	ADD INDEX idx_enrollments_prev_token (previous_host_token_id);
-- +goose StatementEnd
