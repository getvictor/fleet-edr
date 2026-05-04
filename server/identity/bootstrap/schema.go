package bootstrap

import (
	"errors"

	"github.com/go-sql-driver/mysql"
)

// schemaStatements are the CREATE TABLE statements identity owns. Idempotent
// (IF NOT EXISTS); safe to re-run on a populated DB.
var schemaStatements = []string{
	// users table for UI auth. password_hash is argon2id output (32 bytes);
	// password_salt is 16 random bytes (same argon params as enrollment host
	// tokens). email is UNIQUE so duplicate invites fail cleanly at the DB
	// boundary.
	`CREATE TABLE IF NOT EXISTS users (
		id             BIGINT AUTO_INCREMENT PRIMARY KEY,
		email          VARCHAR(255)   NOT NULL,
		password_hash  VARBINARY(255) NOT NULL,
		password_salt  VARBINARY(32)  NOT NULL,
		created_at     TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at     TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                              ON UPDATE CURRENT_TIMESTAMP(6),
		UNIQUE KEY uk_users_email (email)
	)`,
	// sessions table for UI cookie auth. id stores SHA-256(token), where
	// token is 32 random bytes (~256 bits of entropy). The plaintext token
	// lives only in the cookie; preimage resistance means a DB dump does
	// not yield replayable credentials. VARBINARY(32) holds the 32-byte
	// digest exactly. csrf_token is 32 random bytes; compared constant-time
	// against X-Csrf-Token header on unsafe methods.
	`CREATE TABLE IF NOT EXISTS sessions (
		id            VARBINARY(32)  PRIMARY KEY,
		user_id       BIGINT         NOT NULL,
		csrf_token    VARBINARY(32)  NOT NULL,
		created_at    TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		last_seen_at  TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                             ON UPDATE CURRENT_TIMESTAMP(6),
		expires_at    TIMESTAMP(6)   NOT NULL,
		INDEX idx_sessions_expires (expires_at)
	)`,
	// audit_events is the append-only operator audit trail. Append-only is
	// enforced primarily by the application code (no UPDATE/DELETE paths
	// in the audit package, no Update/Delete methods on AuditRecorder)
	// and can be tightened to GRANT-level enforcement in deployments
	// that have a DBA without changing this schema. actor_user_id is
	// nullable so login_failed rows (where the email may map to no user)
	// still record the attempt; actor_email is denormalised so audit
	// remains readable after a user row is deleted. payload is JSON to
	// let individual actions record per-action context (alert prior
	// state, policy diff) without a schema migration. Indexes cover the
	// retrieval queries the admin UI will run: by occurred_at (timeline),
	// by actor (per-user history), by action (filter all logins), and by
	// target (alert history).
	`CREATE TABLE IF NOT EXISTS audit_events (
		id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		occurred_at     TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		actor_user_id   BIGINT          NULL,
		actor_email     VARCHAR(255)    NULL,
		action          VARCHAR(64)     NOT NULL,
		target_type     VARCHAR(64)     NULL,
		target_id       VARCHAR(255)    NULL,
		trace_id        VARCHAR(32)     NULL,
		remote_addr     VARCHAR(64)     NULL,
		payload         JSON            NULL,
		INDEX idx_audit_events_occurred (occurred_at),
		INDEX idx_audit_events_actor (actor_user_id, occurred_at),
		INDEX idx_audit_events_action (action, occurred_at),
		INDEX idx_audit_events_target (target_type, target_id, occurred_at)
	)`,
	// tenants is the wave-1 scaffolding for MSSP-style multi-tenancy. A
	// fresh deployment seeds exactly one row (id='default') and wave-1
	// reads do NOT filter on tenant_id; the column exists everywhere so
	// wave 2's scope work does not require a backfill migration. status
	// is an ENUM rather than a free-form string so an audit-log query
	// for "suspended tenant activity" stays a constant-time index hit.
	`CREATE TABLE IF NOT EXISTS tenants (
		id          VARCHAR(64)  PRIMARY KEY,
		name        VARCHAR(255) NOT NULL,
		status      ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
		created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                         ON UPDATE CURRENT_TIMESTAMP(6)
	)`,
	// identities maps an external auth subject to a local user. provider
	// is 'local_password' for break-glass, 'oidc' for SSO logins, and a
	// future 'api_token' for wave-2 machine identities. subject is the
	// stable IdP claim ('sub' for OIDC) or, for local_password, the
	// user's email at time of seed. UNIQUE(provider, subject) keeps a
	// (provider, subject) tuple bound to exactly one user; the JIT
	// provisioning path inserts here on first SSO login.
	`CREATE TABLE IF NOT EXISTS identities (
		id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
		user_id     BIGINT       NOT NULL,
		provider    VARCHAR(64)  NOT NULL,
		subject     VARCHAR(255) NOT NULL,
		created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		UNIQUE KEY uk_identities_provider_subject (provider, subject),
		INDEX idx_identities_user (user_id)
	)`,
	// roles names the deployment's RBAC roles. id is a stable string
	// because OPA / Rego policy bundles reference roles by name; an
	// integer surrogate would force a JOIN on the hot authz path.
	// is_builtin distinguishes the five seeded roles from any future
	// admin-created ones so the admin API can refuse to delete them.
	`CREATE TABLE IF NOT EXISTS roles (
		id           VARCHAR(64)  PRIMARY KEY,
		display_name VARCHAR(255) NOT NULL,
		description  TEXT         NULL,
		is_builtin   TINYINT(1)   NOT NULL DEFAULT 0,
		created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                          ON UPDATE CURRENT_TIMESTAMP(6)
	)`,
	// role_bindings binds a user to a role at a tenant + scope. wave 1
	// honours scope_type='tenant' only; bindings with 'host_group' or
	// 'host' MAY be persisted (the column is here for non-breaking wave
	// 2 evolution) but the chokepoint denies them with reason
	// scope_not_yet_supported until the resolver ships. expires_at is
	// nullable; the chokepoint treats expired bindings as if they did
	// not exist. The (user_id, expires_at) index covers the primary read
	// pattern: load every live binding for the calling actor.
	`CREATE TABLE IF NOT EXISTS role_bindings (
		id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
		user_id     BIGINT       NOT NULL,
		role_id     VARCHAR(64)  NOT NULL,
		tenant_id   VARCHAR(64)  NOT NULL DEFAULT 'default',
		scope_type  ENUM('tenant', 'host_group', 'host') NOT NULL DEFAULT 'tenant',
		scope_id    VARCHAR(255) NOT NULL DEFAULT '*',
		expires_at  TIMESTAMP(6) NULL,
		created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		INDEX idx_role_bindings_user (user_id, expires_at),
		INDEX idx_role_bindings_role (role_id),
		INDEX idx_role_bindings_tenant (tenant_id)
	)`,
	// bootstrap_tokens backs the single-use redemption flow that
	// replaces "print a generated password to stderr" for break-glass
	// account setup. token_hash is SHA-256 of the random token; the
	// plaintext lives only in the printed redemption URL. user_id is
	// nullable so a generic invite token (wave 2) can mint a user on
	// redemption; the wave-1 break-glass token is pre-bound to the
	// admin user. kind reserves space for future token kinds without a
	// schema change.
	`CREATE TABLE IF NOT EXISTS bootstrap_tokens (
		id           BIGINT        AUTO_INCREMENT PRIMARY KEY,
		token_hash   VARBINARY(32) NOT NULL,
		user_id      BIGINT        NULL,
		kind         VARCHAR(32)   NOT NULL,
		issued_at    TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		expires_at   TIMESTAMP(6)  NOT NULL,
		redeemed_at  TIMESTAMP(6)  NULL,
		UNIQUE KEY uk_bootstrap_tokens_hash (token_hash),
		INDEX idx_bootstrap_tokens_user (user_id),
		INDEX idx_bootstrap_tokens_expiry (expires_at)
	)`,
	// webauthn_credentials persists the WebAuthn authenticators the
	// break-glass account registers. credential_id is the raw
	// (base64url-decoded) credential id from the authenticator;
	// public_key is the COSE-encoded key. sign_count is the
	// authenticator's monotonic counter, used to detect cloned
	// credentials. transports records the available transports the
	// browser advertised at registration time (USB, NFC, BLE, internal).
	// name is operator-visible ("YubiKey Slot 1") to aid rotation.
	`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id            BIGINT          AUTO_INCREMENT PRIMARY KEY,
		user_id       BIGINT          NOT NULL,
		credential_id VARBINARY(255)  NOT NULL,
		public_key    BLOB            NOT NULL,
		sign_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
		transports    VARCHAR(64)     NULL,
		name          VARCHAR(255)    NULL,
		created_at    TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		last_used_at  TIMESTAMP(6)    NULL,
		UNIQUE KEY uk_webauthn_credential (credential_id),
		INDEX idx_webauthn_user (user_id)
	)`,
}

// schemaMigrations are idempotent ALTERs applied after the CREATE TABLEs.
// Errors that mean "already applied" are swallowed by
// isAlreadyAppliedMigration so re-running on a populated DB is a no-op.
var schemaMigrations = []string{
	// FK constraint: enforce that sessions point at live users (CASCADE on
	// user delete so stale sessions die with their owner). Index on the FK
	// column is required for InnoDB to accept the constraint.
	`ALTER TABLE sessions ADD INDEX idx_sessions_user_id (user_id)`,
	`ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`,

	// User-management additive columns. Each ADD COLUMN is idempotent
	// via the 1060 (duplicate column) ignore. tenant_id is the wave-1
	// scaffolding for MSSP work; status lets the admin API disable an
	// account without deleting it; is_breakglass marks the local
	// admin account that the break-glass surface gates on. The MODIFY
	// COLUMN statements relax password_hash and password_salt to NULL
	// so an SSO-only user (no local credentials) can exist; existing
	// rows already have non-NULL values, so the relaxation is purely a
	// constraint change.
	`ALTER TABLE users ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'`,
	`ALTER TABLE users ADD COLUMN display_name VARCHAR(255) NULL`,
	`ALTER TABLE users ADD COLUMN status ENUM('active', 'disabled') NOT NULL DEFAULT 'active'`,
	`ALTER TABLE users ADD COLUMN is_breakglass TINYINT(1) NOT NULL DEFAULT 0`,
	`ALTER TABLE users MODIFY COLUMN password_hash VARBINARY(255) NULL`,
	`ALTER TABLE users MODIFY COLUMN password_salt VARBINARY(32) NULL`,

	// Sessions gain identity_id (which authn identity issued the
	// session) and auth_method ('local_password' for break-glass,
	// 'oidc' for SSO). Existing sessions default to 'local_password'
	// because that's the only flow today; the OIDC path lands in a
	// later phase and will populate identity_id at session creation.
	`ALTER TABLE sessions ADD COLUMN identity_id BIGINT NULL`,
	`ALTER TABLE sessions ADD COLUMN auth_method VARCHAR(32) NOT NULL DEFAULT 'local_password'`,
}

// isAlreadyAppliedMigration returns true when err is one of the MySQL
// "this ALTER is already applied" codes, so we can treat the re-run as a
// no-op.
func isAlreadyAppliedMigration(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	// 1060 duplicate column, 1061 duplicate key name, 1826 duplicate FK name,
	// 1022 duplicate key on add (older MySQL code for FK name clash).
	switch mysqlErr.Number {
	case 1060, 1061, 1826, 1022:
		return true
	}
	return false
}
