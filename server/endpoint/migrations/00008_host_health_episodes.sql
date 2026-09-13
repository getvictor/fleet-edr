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
-- subject is WHICH thing inside the component is at fault, and it is part of the open-episode key. One component can own several
-- independently failing parts: network_extension owns both content_filter and dns_proxy, and the self-heal controller reports each
-- separately, so a key of (host, component, kind) alone would let the second provider's failure collide with the first and be
-- discarded, losing its provider, outcome, and attempt count. It is the empty string for a fault that concerns the component as a
-- whole, which still keys correctly because the empty string is a value like any other here (unlike NULL, which would make every
-- such row distinct and defeat the deduplication).
--
-- open_episode exists to make "at most one OPEN episode per host, component, subject and kind" a schema guarantee rather than a
-- read-then-write in application code, which under concurrent ingest across replicas is a race that would record one outage as several. It is
-- a generated column that is 1 while resolved_at_ns IS NULL and NULL once the episode closes, combined with the unique key below:
-- MySQL treats NULLs in a unique index as distinct, so any number of CLOSED episodes may share a key while at most one open one can
-- exist. That makes re-asserting a fault an INSERT that collides and is ignored, and it makes it impossible for a bug elsewhere to
-- open a second concurrent episode for one outage.
--
-- No foreign key to any host table, matching host_health above: the endpoint context owns this table, and cross-context FKs are
-- deliberately avoided here.
CREATE TABLE IF NOT EXISTS host_health_episodes (
	id            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
	host_id       VARCHAR(255) NOT NULL,
	component     VARCHAR(64)  NOT NULL,
	subject       VARCHAR(128) NOT NULL DEFAULT '',
	kind          VARCHAR(64)  NOT NULL,
	severity      VARCHAR(16)  NOT NULL,
	title         VARCHAR(255) NOT NULL,
	description   TEXT         NULL,
	detail        JSON         NULL,
	opened_at_ns  BIGINT       NOT NULL,
	resolved_at_ns BIGINT      NULL,
	created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
	open_episode  TINYINT GENERATED ALWAYS AS (CASE WHEN resolved_at_ns IS NULL THEN 1 ELSE NULL END) VIRTUAL,
	UNIQUE KEY uniq_host_health_open (host_id, component, subject, kind, open_episode),
	INDEX idx_host_health_episodes_host (host_id, opened_at_ns),
	INDEX idx_host_health_episodes_open (open_episode, opened_at_ns)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS host_health_episodes;
-- +goose StatementEnd
