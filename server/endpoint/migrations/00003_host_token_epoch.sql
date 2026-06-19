-- +goose Up
-- +goose StatementBegin
-- token_epoch backs revocation for self-validating signed host tokens. The token carries the epoch it was minted at; the verify path
-- rejects any token whose epoch is below the host's current token_epoch. Operator-driven credential cycling bumps this column; the
-- per-replica revocation snapshot reads it. Default 0: a never-cycled host issues and accepts epoch-0 tokens.
ALTER TABLE enrollments
	ADD COLUMN token_epoch INT NOT NULL DEFAULT 0 AFTER host_token_issued_at;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE enrollments
	DROP COLUMN token_epoch;
-- +goose StatementEnd
