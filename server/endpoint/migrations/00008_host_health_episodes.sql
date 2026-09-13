-- +goose Up
-- +goose StatementBegin
-- host_health_episodes is the durable account of component faults that needed a person (issue #778). It is the counterpart to
-- host_health, which is current-state: a level table reports what is true now and is overwritten the moment that changes, so a host
-- that stopped capturing and was later fixed by hand reads healthy afterwards and leaves no record it was ever blind. That was the
-- job the alert row was doing, and it is the reason the signal could not simply be dropped from the alerts table when it stopped
-- being a detection. An episode is the shape the fact actually has: it begins, it ends, and the interval is the answer an operator
-- wants (the motivating incident was 37.8 hours of a host not capturing, a number that previously had to be reconstructed by hand
-- from an event archive).
--
-- kind is the machine name of the fault, open-vocabulary for the same reason the health snapshot's component types and reasons are:
-- a new health signal should be a producer-side change, not a schema migration. detail is the fault's own machine-readable fields as
-- a JSON document (for self_heal_failed: the provider, the outcome, and the attempt count), so a reader gets them as fields instead
-- of parsing them back out of prose.
--
-- subject is WHICH thing inside the component is at fault (for a capture-provider failure, the provider). It is data an operator
-- reads and filters on, not part of the identity: the identity is the occurrence below.
--
-- source_event_id is the occurrence identity, and (host_id, source_event_id) is what deduplicates. It is the same identity the alert
-- this replaced used, for the same reason: the producer emits ONE event per outage (the agent's self-heal escalates health level
-- state on every later report but fires the event only at the edge where its repair budget is spent), so the only repetition the
-- server sees is REDELIVERY of that one event. Event delivery is at-least-once, so a batch can be evaluated, acked poorly, and
-- evaluated again.
--
-- An earlier cut of this keyed "at most one OPEN episode per host, component, subject and kind" through a generated column instead.
-- That was built for a repetition that does not happen, and it broke on the one that does: once the episode closed, the key no
-- longer matched, so a redelivered event opened a second episode for an outage that was already recorded and resolved. Keying on the
-- occurrence handles both shapes, needs no generated column, and lets a genuinely later outage open its own episode because it
-- carries its own event.
--
-- No foreign key to any host table, matching host_health above: the endpoint context owns this table, and cross-context FKs are
-- deliberately avoided here.
CREATE TABLE IF NOT EXISTS host_health_episodes (
	id              BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
	host_id         VARCHAR(255) NOT NULL,
	component       VARCHAR(64)  NOT NULL,
	subject         VARCHAR(128) NOT NULL DEFAULT '',
	kind            VARCHAR(64)  NOT NULL,
	source_event_id VARCHAR(255) NOT NULL,
	severity        VARCHAR(16)  NOT NULL,
	title           VARCHAR(255) NOT NULL,
	description     TEXT         NULL,
	detail          JSON         NULL,
	opened_at_ns    BIGINT       NOT NULL,
	resolved_at_ns  BIGINT       NULL,
	created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE KEY uniq_host_health_occurrence (host_id, source_event_id),
	INDEX idx_host_health_episodes_host (host_id, opened_at_ns),
	-- The open-episodes read ("which hosts need attention now") and the per-component close both scan on these.
	INDEX idx_host_health_episodes_open (resolved_at_ns, opened_at_ns),
	INDEX idx_host_health_episodes_component (host_id, component, resolved_at_ns)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS host_health_episodes;
-- +goose StatementEnd
