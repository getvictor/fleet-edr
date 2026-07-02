-- +goose Up
-- +goose StatementBegin
-- Host inventory columns (issue #579): the status check-in now refreshes the host's self-reported identity, so the enrollment row
-- becomes "latest known identity" rather than "identity at enroll time". os_name and os_build join the existing hostname /
-- agent_version / os_version columns (which the check-in also refreshes); enrolled_at keeps recording enrollment time.
-- inventory_reported_at_ns is the agent-stamped time of the report that last wrote the identity fields: it orders concurrent check-ins
-- across replicas (same last-writer-wins role reported_at_ns plays on host_health) and lets a reader show identity staleness honestly.
-- Zero means no check-in has refreshed this row yet. Note a re-enroll also refreshes hostname/os_version/agent_version (its ON
-- DUPLICATE KEY path) without touching this stamp or os_name/os_build, so the stamp dates the last CHECK-IN write, not the identity
-- values' provenance.
ALTER TABLE enrollments
	ADD COLUMN os_name VARCHAR(255) NOT NULL DEFAULT '',
	ADD COLUMN os_build VARCHAR(255) NOT NULL DEFAULT '',
	ADD COLUMN inventory_reported_at_ns BIGINT NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE enrollments
	DROP COLUMN os_name,
	DROP COLUMN os_build,
	DROP COLUMN inventory_reported_at_ns;
-- +goose StatementEnd
