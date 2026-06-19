-- +goose Up
-- +goose StatementBegin
-- token_epoch backs revocation for self-validating signed host tokens. The token carries the epoch it was minted at; the verify path
-- rejects any token whose epoch is below the host's current token_epoch. Operator-driven credential cycling bumps this column; the
-- per-replica revocation snapshot reads it. Default 0: a never-cycled host issues and accepts epoch-0 tokens.
-- The revocation snapshot reloads `WHERE token_epoch > 0 OR revoked_at IS NOT NULL` every few seconds on every replica. Index BOTH
-- columns so MySQL can index_merge (union) that OR instead of full-scanning the table: an index on token_epoch alone would not be used
-- while revoked_at is unindexed. The result set (revoked or cycled hosts) is tiny, so the indexed read stays cheap at fleet scale.
-- BIGINT (not INT) to match the int64 the runtime model carries (signedtoken.Claims.Epoch, store.TokenStatus, RevocationEntries): a
-- 32-bit column could overflow under enough operator-driven cycles and silently break credential cycling.
ALTER TABLE enrollments
	ADD COLUMN token_epoch BIGINT NOT NULL DEFAULT 0 AFTER host_token_issued_at,
	ADD INDEX idx_enrollments_token_epoch (token_epoch),
	ADD INDEX idx_enrollments_revoked_at (revoked_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Dropping token_epoch also drops idx_enrollments_token_epoch; idx_enrollments_revoked_at must be dropped explicitly.
ALTER TABLE enrollments
	DROP INDEX idx_enrollments_revoked_at,
	DROP COLUMN token_epoch;
-- +goose StatementEnd
