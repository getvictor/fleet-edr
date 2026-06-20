-- +goose Up
-- app_config is the deployment's general settings store: a single versioned JSON document deserialized into a typed Go struct
-- (server/identity/internal/appconfig). This is the scalable home for admin-editable, non-secret, non-relational settings (external
-- URL today; org name, retention, feature toggles later): a new setting is a new struct field with NO migration. Secrets never live
-- here (they go in dedicated sealed columns, e.g. oidc_config.client_secret_enc); strongly-relational config gets its own typed table.
-- Singleton (CHECK id = 1). version is an optimistic-concurrency / cache-invalidation counter bumped on every write, mirroring
-- oidc_config.config_version.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS app_config (
	id          TINYINT      NOT NULL DEFAULT 1,
	config      JSON         NOT NULL,
	version     BIGINT       NOT NULL DEFAULT 1,
	updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
	                         ON UPDATE CURRENT_TIMESTAMP(6),
	updated_by  BIGINT       NULL,
	PRIMARY KEY (id),
	CONSTRAINT chk_app_config_singleton CHECK (id = 1),
	CONSTRAINT fk_app_config_updated_by FOREIGN KEY (updated_by)
		REFERENCES users(id) ON DELETE SET NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_config;
-- +goose StatementEnd
