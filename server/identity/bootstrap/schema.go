package bootstrap

// schemaStatements are the CREATE TABLE statements identity owns. Idempotent
// (IF NOT EXISTS); safe to re-run on a populated DB.
//
// Order is load-bearing: every FK target is created before the referencing
// table. The dependency tree:
//
//	users (no deps)
//	roles (no deps)
//	identities (-> users)
//	role_bindings (-> users, roles)
//	bootstrap_tokens (-> users)
//	webauthn_credentials (-> users)
//	sessions (-> users, identities)
//	audit_events (no FK; actor_user_id stays unconstrained because login_failed
//	             rows record an attempted email even when no user exists)
//
// The product hasn't shipped, so there are no upgrade-path migrations to
// preserve. Every column the wave-1 user-management spec adds lives inline
// in its CREATE TABLE rather than as a separate ALTER. If a future schema
// change requires touching this set after release, it lands as a migration
// in a new file (or as a recreate-DB note in the change proposal); we do
// NOT accumulate ALTER deltas during the pre-release iteration.
var schemaStatements = []string{
	// users is the operator-account row. password_hash + password_salt
	// are NULLABLE because an SSO-only user has no local credential; the
	// argon2id parameter set still mirrors the enrollment host-token
	// hash so a future passcrypto consolidation is mechanical. status
	// lets the admin API disable an account without deleting it (audit
	// rows + role-binding history stay intact). is_breakglass marks the
	// single account the break-glass surface gates on.
	`CREATE TABLE IF NOT EXISTS users (
		id             BIGINT AUTO_INCREMENT PRIMARY KEY,
		email          VARCHAR(255)   NOT NULL,
		display_name   VARCHAR(255)   NULL,
		status         ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
		is_breakglass  TINYINT(1)     NOT NULL DEFAULT 0,
		password_hash  VARBINARY(255) NULL,
		password_salt  VARBINARY(32)  NULL,
		created_at     TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at     TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                              ON UPDATE CURRENT_TIMESTAMP(6),
		UNIQUE KEY uk_users_email (email)
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
	// identities maps an external auth subject to a local user. provider
	// is 'local_password' for break-glass, 'oidc' for SSO logins, and a
	// future 'api_token' for wave-2 machine identities. subject is the
	// stable IdP claim ('sub' for OIDC) or, for local_password, the
	// user's email at time of seed. UNIQUE(provider, subject) keeps a
	// (provider, subject) tuple bound to exactly one user; the JIT
	// provisioning path inserts here on first SSO login. CASCADE on
	// user delete so a deleted user takes its identity rows with it.
	`CREATE TABLE IF NOT EXISTS identities (
		id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
		user_id     BIGINT       NOT NULL,
		provider    VARCHAR(64)  NOT NULL,
		subject     VARCHAR(255) NOT NULL,
		created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		UNIQUE KEY uk_identities_provider_subject (provider, subject),
		INDEX idx_identities_user (user_id),
		CONSTRAINT fk_identities_user FOREIGN KEY (user_id)
			REFERENCES users(id) ON DELETE CASCADE
	)`,
	// role_bindings binds a user to a role at a given scope. The product
	// is a single-instance deployment, so the only scope wave 1 honours
	// is 'global' (meaning "deployment-wide"); other scope_type values
	// ('host_group', 'host') MAY be persisted (the column is here for
	// non-breaking wave 2 evolution) but the chokepoint denies them with
	// reason scope_not_yet_supported until the resolver ships.
	// expires_at is nullable; the chokepoint treats expired bindings as
	// if they did not exist. user_id CASCADE on user delete; role_id
	// RESTRICT so the admin path cannot retire a role that still has
	// bindings.
	`CREATE TABLE IF NOT EXISTS role_bindings (
		id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
		user_id     BIGINT       NOT NULL,
		role_id     VARCHAR(64)  NOT NULL,
		scope_type  ENUM('global', 'host_group', 'host') NOT NULL DEFAULT 'global',
		scope_id    VARCHAR(255) NOT NULL DEFAULT '*',
		expires_at  TIMESTAMP(6) NULL,
		created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		UNIQUE KEY uk_role_bindings (user_id, role_id, scope_type, scope_id),
		INDEX idx_role_bindings_user (user_id, expires_at),
		INDEX idx_role_bindings_role (role_id),
		CONSTRAINT fk_role_bindings_user FOREIGN KEY (user_id)
			REFERENCES users(id) ON DELETE CASCADE,
		CONSTRAINT fk_role_bindings_role FOREIGN KEY (role_id)
			REFERENCES roles(id) ON DELETE RESTRICT
	)`,
	// bootstrap_tokens backs the single-use redemption flow that
	// replaces "print a generated password to stderr" for break-glass
	// account setup. token_hash is SHA-256 of the random token; the
	// plaintext lives only in the printed redemption URL. user_id is
	// nullable so a generic invite token (wave 2) can mint a user on
	// redemption; the wave-1 break-glass token is pre-bound to the
	// admin user. kind reserves space for future token kinds without a
	// schema change. CASCADE on user delete reaps any unredeemed tokens
	// for a deleted user.
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
		INDEX idx_bootstrap_tokens_expiry (expires_at),
		CONSTRAINT fk_bootstrap_tokens_user FOREIGN KEY (user_id)
			REFERENCES users(id) ON DELETE CASCADE
	)`,
	// webauthn_credentials persists the WebAuthn authenticators the
	// break-glass account registers. credential_id is the raw
	// (base64url-decoded) credential id from the authenticator;
	// public_key is the COSE-encoded key. sign_count is the
	// authenticator's monotonic counter, used to detect cloned
	// credentials. transports records the available transports the
	// browser advertised at registration time (USB, NFC, BLE, internal).
	// name is operator-visible ("YubiKey Slot 1") to aid rotation.
	// CASCADE on user delete so a removed user's authenticators do not
	// linger.
	`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id               BIGINT          AUTO_INCREMENT PRIMARY KEY,
		user_id          BIGINT          NOT NULL,
		credential_id    VARBINARY(255)  NOT NULL,
		public_key       BLOB            NOT NULL,
		sign_count       BIGINT UNSIGNED NOT NULL DEFAULT 0,
		transports       VARCHAR(64)     NULL,
		name             VARCHAR(255)    NULL,
		-- backup_eligible: the BE flag the authenticator advertised at
		-- registration. INVARIANT per the WebAuthn spec; the library
		-- rejects logins where the asserted BE differs from this
		-- stored value. Persisted so platform-authenticator Passkeys
		-- (iCloud Keychain, Google Password Manager, Windows Hello
		-- with sync) work past the first login.
		backup_eligible  TINYINT(1)      NOT NULL DEFAULT 0,
		-- backup_state: the BS flag. Spec allows 0->1 transitions
		-- (when a credential first gets backed up); 1->0 is rejected.
		-- Updated on every successful login so subsequent logins see
		-- the current state.
		backup_state     TINYINT(1)      NOT NULL DEFAULT 0,
		created_at       TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		last_used_at     TIMESTAMP(6)    NULL,
		UNIQUE KEY uk_webauthn_credential (credential_id),
		INDEX idx_webauthn_user (user_id),
		CONSTRAINT fk_webauthn_user FOREIGN KEY (user_id)
			REFERENCES users(id) ON DELETE CASCADE
	)`,
	// sessions backs UI cookie auth. id stores SHA-256(token), where
	// token is 32 random bytes (~256 bits of entropy). The plaintext
	// token lives only in the cookie; preimage resistance means a DB
	// dump does not yield replayable credentials. csrf_token is 32
	// random bytes; compared constant-time against X-Csrf-Token header
	// on unsafe methods. identity_id records which authn identity
	// issued the session (NULL for legacy local-password sessions);
	// auth_method records the flow that produced the session.
	// fk_sessions_user CASCADE: deleting a user kills every session.
	// fk_sessions_identity CASCADE: deleting an identity (e.g. SSO
	// subject rebind, break-glass credential rotation) kills the
	// derived sessions; sessions with NULL identity_id are unaffected.
	`CREATE TABLE IF NOT EXISTS sessions (
		id            VARBINARY(32)  PRIMARY KEY,
		user_id       BIGINT         NOT NULL,
		identity_id   BIGINT         NULL,
		auth_method   VARCHAR(32)    NOT NULL DEFAULT 'local_password',
		csrf_token    VARBINARY(32)  NOT NULL,
		created_at    TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		last_seen_at  TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                             ON UPDATE CURRENT_TIMESTAMP(6),
		last_auth_at  TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		expires_at    TIMESTAMP(6)   NOT NULL,
		INDEX idx_sessions_expires (expires_at),
		INDEX idx_sessions_user_id (user_id),
		INDEX idx_sessions_identity_id (identity_id),
		CONSTRAINT fk_sessions_user FOREIGN KEY (user_id)
			REFERENCES users(id) ON DELETE CASCADE,
		CONSTRAINT fk_sessions_identity FOREIGN KEY (identity_id)
			REFERENCES identities(id) ON DELETE CASCADE
	)`,
	// last_auth_at tracks the most recent authentication event for the
	// session — initial login, OIDC callback re-use during reauth, or
	// break-glass reauth POST. Phase 5's reauth window compares it to
	// NOW() to compute Actor.SessionFresh; destructive actions
	// (host.isolate, host.kill_process, host.run_script,
	// alert.resolve when severity=critical) deny with reason
	// "reauth_required" when SessionFresh is false. Distinct from
	// last_seen_at, which tracks any authenticated request and is the
	// idle-timeout source.
	// audit_events is the append-only operator audit trail. Append-only is
	// enforced primarily by the application code (no UPDATE/DELETE paths
	// in the audit package, no Update/Delete methods on AuditRecorder)
	// and can be tightened to GRANT-level enforcement in deployments
	// that have a DBA without changing this schema. actor_user_id is
	// nullable AND deliberately unconstrained: login_failed rows record
	// the attempted email even when no user exists, and audit retention
	// must outlive user-row lifetime so that a deleted user's history
	// stays readable. actor_email is denormalised so audit remains
	// readable after a user row is deleted. payload is JSON to let
	// individual actions record per-action context (alert prior state,
	// policy diff) without a schema migration.
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
}
