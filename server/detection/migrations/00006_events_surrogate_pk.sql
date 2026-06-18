-- +goose Up
-- Replace the 36-character UUID primary key with a compact BIGINT surrogate, keeping event_id as a UNIQUE key (issue #408). InnoDB
-- copies the primary key into every secondary-index leaf, so a VARCHAR(255) event_id holding a 36-byte UUID inflates every secondary
-- index by ~36 bytes/row; an 8-byte surrogate shrinks all of them. event_id stays the logical unique identity on the wire and in
-- every query, so the change is invisible to callers:
--   - INSERT IGNORE still dedups on the event_id unique constraint (idempotent submission contract unchanged).
--   - The alert_events.event_id foreign key still references events(event_id): a FK may target a UNIQUE key, not only the PK.
--   - Every query that selects/joins/filters event_id as a string is unchanged.
--
-- Two ordered steps so the alert_events FK never loses its required index on event_id: add the UNIQUE key first (event_id then has
-- both the old PK and the new unique index), then swap the PK. After DROP PRIMARY KEY the FK relies on uk_events_event_id, which
-- already exists.
--
-- COST: swapping the clustered key rebuilds the table (InnoDB cannot change the PK in place). On a large existing events table this
-- is a one-time, write-blocking rebuild best run in a maintenance window; on a fresh install it is free. The diet is most effective
-- measured against the reduced row set from the heartbeat-drop and network/DNS-coalescing changes (issue #408), so it lands with them.

-- +goose StatementBegin
ALTER TABLE events ADD UNIQUE KEY uk_events_event_id (event_id);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE events
	DROP PRIMARY KEY,
	ADD COLUMN id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;
-- +goose StatementEnd

-- +goose Down
-- Intentionally a no-op. Reverting to a UUID primary key would require another full table rebuild and dropping the surrogate every
-- row now carries; migrations are forward-only (ADR-0009) and the rollback path is restore-from-backup.
