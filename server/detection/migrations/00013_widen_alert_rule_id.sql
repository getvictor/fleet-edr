-- +goose Up
-- Widen alerts.rule_id from VARCHAR(64) to VARCHAR(255), matching api.MaxRuleIDLen (issue #832).
--
-- The imported SigmaHQ rules (#764) derive their identifiers from upstream filenames, and one shipped rule,
-- proc_creation_macos_remote_access_tools_teamviewer_incoming_connection, is 70 characters. MySQL in strict mode REJECTS an
-- over-long insert rather than truncating it, and alert persistence is deliberately not isolated per rule, so the error fails the
-- batch, the batch is nacked and re-claimed, and nothing caps the attempts. One such rule matching on a host therefore stops that
-- host's queue draining at all: detection for the host ends, not just for that rule. It has not fired yet only because every
-- imported rule ships in monitor mode, where the alert is suppressed before it reaches this table.
--
-- ALGORITHM=INPLACE, LOCK=NONE is stated rather than left to the engine, and it was verified against the pinned MySQL 8.4.9 before
-- being written here: no table rebuild and no write lock. That is a property of the specific widening, not luck. utf8mb4
-- VARCHAR(64) is 256 octets, already past the 255-byte boundary where InnoDB switches to a two-byte length prefix, and
-- VARCHAR(255) at 1020 octets keeps that same prefix, so no row format changes. Had this column been VARCHAR(63) or narrower, the
-- identical widening would have forced a copy.
--
-- Explicit because this table holds data on a live ingest path. An ALTER that silently falls back to ALGORITHM=COPY takes a write
-- lock on alerts for the duration of the copy, which drops telemetry quietly; one that fails loudly is a server that does not
-- start, which is visible and fixable. If a future engine rejects INPLACE here, decide deliberately whether to accept the copy
-- rather than discovering the lock in production.

-- +goose StatementBegin
ALTER TABLE alerts MODIFY COLUMN rule_id VARCHAR(255) NOT NULL, ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd

-- +goose Down
-- Narrowing is NOT the mirror of widening: it is rejected INPLACE ("Cannot change column type INPLACE") because it can lose data,
-- so it needs a full copy. Measured, not assumed. It also fails outright if any stored identifier is longer than 64 characters,
-- which is the correct behaviour: it refuses rather than truncating an identifier that alerts are keyed by.
-- +goose StatementBegin
ALTER TABLE alerts MODIFY COLUMN rule_id VARCHAR(64) NOT NULL, ALGORITHM=COPY;
-- +goose StatementEnd
