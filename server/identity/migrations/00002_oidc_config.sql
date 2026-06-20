-- +goose Up
-- oidc_config holds the deployment's single OIDC provider configuration as durable, runtime-editable state (issue #375). Before this
-- table the OIDC provider was built once at boot from EDR_OIDC_* env vars; now those env vars only seed this row on first boot and the
-- row is the runtime source of truth thereafter (env-seeds / DB-governs precedence). A single deployment has exactly one provider, so
-- the table is a singleton: the CHECK keeps id pinned to 1 and every read/write targets WHERE id = 1.

-- +goose StatementBegin
-- client_secret_enc is the AES-256-GCM sealed client secret (nonce || ciphertext||tag) under the keyring label
-- edr/oidc/client-secret/v1; the plaintext secret never touches the database and is never returned over the API (write-only rotate).
-- NULL means no secret is set yet. scopes is a comma-joined list (read-only at openid,email,profile this wave; the column carries it
-- durably so a future groups-claim wave can edit it). config_version bumps on every update so a replica's in-process provider cache
-- (keyed by issuer) and any future stamp-based invalidation can detect a change without shared state. updated_by FKs users with SET
-- NULL so an env-seed (no operator) or a later user deletion leaves the row intact for audit continuity.
CREATE TABLE IF NOT EXISTS oidc_config (
	id                 TINYINT         NOT NULL DEFAULT 1,
	issuer             VARCHAR(2048)   NOT NULL,
	client_id          VARCHAR(512)    NOT NULL,
	client_secret_enc  VARBINARY(1024) NULL,
	-- external_url is the deployment's externally-reachable base URL (e.g. https://edr.acme.com). The OIDC redirect URI registered at
	-- the IdP is DERIVED from it (external_url + /api/auth/callback) and shown read-only in the UI, so the operator maintains one value.
	-- It is deployment-level (not OIDC-specific) and will move to a General settings section when one lands; it lives here for now
	-- because SSO is its only consumer this wave.
	external_url       VARCHAR(2048)   NOT NULL,
	scopes             VARCHAR(1024)   NOT NULL DEFAULT 'openid,email,profile',
	jit_enabled        TINYINT(1)      NOT NULL DEFAULT 1,
	default_role       VARCHAR(64)     NOT NULL DEFAULT 'analyst',
	config_version     BIGINT          NOT NULL DEFAULT 1,
	updated_at         TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
	                                  ON UPDATE CURRENT_TIMESTAMP(6),
	updated_by         BIGINT          NULL,
	PRIMARY KEY (id),
	CONSTRAINT chk_oidc_config_singleton CHECK (id = 1),
	CONSTRAINT fk_oidc_config_updated_by FOREIGN KEY (updated_by)
		REFERENCES users(id) ON DELETE SET NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oidc_config;
-- +goose StatementEnd
