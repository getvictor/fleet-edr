-- +goose Up
-- macOS uid_t/gid_t are unsigned 32-bit. The `nobody` account is 4294967294 (-2 as uint32) and the "no uid" sentinel
-- KAUTH_UID_NONE is 4294967295 (-1); both overflow a signed INT (max 2147483647) and make the process insert fail with MySQL
-- error 1264 (out of range). That failure previously wedged the graph-builder batch loop: the poison row was re-fetched and
-- re-failed every cycle, so the detection pipeline stalled fleet-wide and produced no further process graph or alerts. Widen
-- uid/gid to INT UNSIGNED to hold the full uid_t/gid_t range. Existing rows hold only 0..2147483647 (the signed range that ever
-- inserted successfully), so the widening is lossless.

-- +goose StatementBegin
ALTER TABLE processes
	MODIFY uid INT UNSIGNED,
	MODIFY gid INT UNSIGNED;
-- +goose StatementEnd

-- +goose Down
-- Intentionally a no-op. Narrowing uid/gid back to a signed INT would fail (or silently corrupt) on any row that has since stored a
-- value above 2147483647, e.g. nobody = 4294967294, so a real rollback is unsafe and would reintroduce the overflow bug. Migrations
-- are forward-only (ADR-0009); this Down deliberately does nothing.
