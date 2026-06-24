-- +goose Up
-- trace_sampler_settings is the deployment's runtime OTel trace head-sampling configuration (issue #374): the per-tier sample ratios
-- and a force-full incident toggle. Each replica polls this row and atomically swaps its live sampler, so support can dial telemetry
-- volume up or down without a redeploy. Singleton (CHECK id = 1). The ratios are bounded by CHECK constraints so a bad write is rejected
-- at the DB even if the API validation is bypassed. updated_by records the operator user id as a breadcrumb; it is intentionally NOT a
-- foreign key to identity's users table (this is a separate bounded context's corpus, and the audit log is the authoritative record of
-- who changed what). The seeded ratios match the sampler's compile-time defaults (internal/observability/tracing: 0.01 high-volume,
-- 0.1 standard) so a replica that has polled the row samples identically to one that has not.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS trace_sampler_settings (
	id                TINYINT      NOT NULL DEFAULT 1,
	high_volume_ratio DOUBLE       NOT NULL DEFAULT 0.01,
	standard_ratio    DOUBLE       NOT NULL DEFAULT 0.1,
	force_full        BOOLEAN      NOT NULL DEFAULT FALSE,
	version           BIGINT       NOT NULL DEFAULT 1,
	updated_at        TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
	                              ON UPDATE CURRENT_TIMESTAMP(6),
	updated_by        BIGINT       NULL,
	PRIMARY KEY (id),
	CONSTRAINT chk_trace_sampler_singleton CHECK (id = 1),
	CONSTRAINT chk_trace_sampler_high_volume_ratio CHECK (high_volume_ratio BETWEEN 0 AND 1),
	CONSTRAINT chk_trace_sampler_standard_ratio CHECK (standard_ratio BETWEEN 0 AND 1)
);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO trace_sampler_settings (id, high_volume_ratio, standard_ratio, force_full)
VALUES (1, 0.01, 0.1, FALSE)
ON DUPLICATE KEY UPDATE id = id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS trace_sampler_settings;
-- +goose StatementEnd
