-- +goose Up
-- service_accounts holds non-human API principals (issue #376, ADR-0013). A service account authenticates with a long-lived client
-- credential (client_id + secret) that is exchanged at the token endpoint for a short-lived self-validating access token; the secret is
-- stored only as a SHA-256 hash, never plaintext, and is shown once at creation/rotation. epoch is the revocation generation: a revoke
-- or disable bumps it, and the per-replica revocation snapshot rejects any outstanding access token carrying a stale epoch (mirrors the
-- #454 host-token mechanism). The bound role MUST NOT be admin/super_admin or any role granting console-management actions; that rule
-- is enforced in the application layer (the role set is dynamic), not by a CHECK here.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS service_accounts (
	id           BIGINT       AUTO_INCREMENT PRIMARY KEY,
	client_id    VARCHAR(64)  NOT NULL,
	name         VARCHAR(255) NOT NULL,
	role_id      VARCHAR(64)  NOT NULL,
	secret_hash  VARBINARY(32) NOT NULL,
	epoch        BIGINT       NOT NULL DEFAULT 0,
	created_by   BIGINT       NULL,
	expires_at   TIMESTAMP(6) NOT NULL,
	revoked_at   TIMESTAMP(6) NULL,
	last_used_at TIMESTAMP(6) NULL,
	created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	UNIQUE KEY uk_service_accounts_client_id (client_id),
	INDEX idx_service_accounts_created (created_at),
	CONSTRAINT fk_service_accounts_role FOREIGN KEY (role_id)
		REFERENCES roles(id) ON DELETE RESTRICT,
	CONSTRAINT fk_service_accounts_created_by FOREIGN KEY (created_by)
		REFERENCES users(id) ON DELETE SET NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS service_accounts;
-- +goose StatementEnd
