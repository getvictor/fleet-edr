-- +goose Up
-- +goose StatementBegin
-- host_health is the endpoint context's latest per-host agent health snapshot: the extensible agent-health check-in (issue #359). It is
-- a current-state table, not an event log. Each POST /api/status upserts the row keyed by host_id, last-writer-wins by reported_at_ns, so
-- a missed post self-heals on the next one and there is exactly one row per host.
--
-- overall_status is the server-computed worst-of rollup of the components (unhealthy > degraded > healthy; unknown when no component is
-- reported), stored denormalized and indexed so the Hosts list join reads a single column and the "hosts needing attention" filter is an
-- indexed lookup rather than a JSON unpack. components is the full ComponentHealth list exactly as the agent sent it, as a JSON document
-- (NULL when the snapshot carried no components); the operator read paths pass it through verbatim, so a future component type needs no
-- schema change here. reported_at_ns is the agent-stamped snapshot time that orders concurrent posts across replicas.
--
-- No foreign key to enrollments or hosts: the endpoint context owns this table and cross-context FKs are deliberately avoided (a host
-- may post health before any other row exists, and ordering with other contexts' migrations is not load-bearing).
CREATE TABLE IF NOT EXISTS host_health (
	host_id        VARCHAR(255) PRIMARY KEY,
	overall_status VARCHAR(16)  NOT NULL,
	components     JSON         NULL,
	reported_at_ns BIGINT       NOT NULL,
	updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	INDEX idx_host_health_overall (overall_status)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS host_health;
-- +goose StatementEnd
