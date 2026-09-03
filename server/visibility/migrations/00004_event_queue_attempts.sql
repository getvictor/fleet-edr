-- +goose Up
-- Bound how long a failing work batch is retried, so it stops stalling its host (issue #836).
--
-- Nack returns a batch with `processed = 0` and the claim selects a host's work ORDER BY timestamp_ns, so a nacked batch is that
-- host's oldest pending work and the next claim takes it again. There was no attempt counter and no abandonment, so a batch that
-- failed DETERMINISTICALLY was retried forever and nothing newer for that host was ever claimed: the process graph stopped
-- advancing and every detection rule stopped seeing that host, not just the rule or event that failed. At a 500ms tick that is
-- roughly 120 attempts a minute, silently.
--
-- Two bound columns rather than one, because one bound cannot tell the two failure shapes apart. attempts alone would set aside
-- anything that failed for ten seconds; time-since-first-failure alone would set aside a batch that failed once and then sat
-- because the host went quiet. A batch is set aside only when BOTH bounds are exceeded; the thresholds and their reasoning live
-- next to the Nack that applies them.
--
-- set_aside_at_ns is a THIRD column rather than a reuse of first_failed_at_ns, because the two answer different questions and the
-- retention sweep needs the second one. first_failed_at_ns is when the batch first failed; set_aside_at_ns is when it was actually
-- withdrawn, which is at least the duration bound later and can be very much later, since attempts accrue only while the host is
-- online. A host that fails a batch once, goes offline for longer than the retention window, then comes back and fails it to the
-- attempt bound would be withdrawn and then immediately swept, leaving no window to inspect it in. Ageing on withdrawal is also
-- what the requirement says ("events set aside longer ago than the configured retention window").

-- +goose StatementBegin
ALTER TABLE event_queue
    ADD COLUMN attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN first_failed_at_ns BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN set_aside_at_ns BIGINT NOT NULL DEFAULT 0,
    ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd

-- The retention sweep for set-aside entries (processed = 3) deletes by age across every host, so it needs an index that leads with
-- the state. The existing idx_event_queue_claim leads with (processed, host_id, timestamp_ns) and would serve a per-host lookup,
-- but the sweep is fleet-wide and orders by when the entry was withdrawn.
--
-- Nothing indexes first_failed_at_ns: it is only ever read in the set-aside promotion, whose other predicate is an event_id IN
-- list already served by the primary key, so an index on it would be written on every nack and read by nothing.
-- +goose StatementBegin
CREATE INDEX idx_event_queue_set_aside ON event_queue (processed, set_aside_at_ns);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_event_queue_set_aside ON event_queue;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE event_queue
    DROP COLUMN attempts,
    DROP COLUMN first_failed_at_ns,
    DROP COLUMN set_aside_at_ns,
    ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd
