package bootstrap

// schemaStatements are the CREATE TABLE statements endpoint owns.
// Idempotent (IF NOT EXISTS); safe to re-run on a populated DB.
var schemaStatements = []string{
	// host_token_id is SHA-256 of the bearer token. It is a
	// deterministic lookup key so Verify can fetch a single candidate
	// row by indexed equality rather than scan every active row. The
	// argon2id hash+salt is still the authenticator -- token_id is
	// one-way, so leaking the column does not let an attacker recover
	// the token. UNIQUE prevents accidental collisions from two hosts
	// somehow winning the 2^-256 lottery.
	//
	// host_token_issued_at tracks per-token issuance (not per-enrollment).
	// On enroll it equals enrolled_at; rotation bumps it to NOW() so the
	// service can decide "this token has lived too long" without keeping
	// a separate rotation-history row. previous_host_token_* + the
	// expires_at peer column are the grace-window state: when rotation
	// flips, the prior (id, hash, salt) is captured here so verify can
	// fall through to it for a bounded window. Both rotation columns are
	// NULL outside an active grace window. See #86 for the full rotation
	// contract.
	`CREATE TABLE IF NOT EXISTS enrollments (
		host_id                    VARCHAR(255)   PRIMARY KEY,
		host_token_id              VARBINARY(32)  NOT NULL,
		host_token_hash            VARBINARY(255) NOT NULL,
		host_token_salt            VARBINARY(32)  NOT NULL,
		host_token_issued_at       TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		previous_host_token_id     VARBINARY(32)  NULL,
		previous_host_token_hash   VARBINARY(255) NULL,
		previous_host_token_salt   VARBINARY(32)  NULL,
		previous_token_expires_at  TIMESTAMP(6)   NULL,
		hostname                   VARCHAR(255)   NOT NULL,
		agent_version              VARCHAR(64)    NOT NULL,
		os_version                 VARCHAR(128)   NOT NULL,
		source_ip                  VARCHAR(45)    NOT NULL,
		tenant_id                  VARCHAR(64)    NOT NULL DEFAULT 'default',
		enrolled_at                TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		expires_at                 TIMESTAMP(6)   NULL,
		revoked_at                 TIMESTAMP(6)   NULL,
		revoke_reason              VARCHAR(128)   NULL,
		revoked_by                 VARCHAR(255)   NULL,
		UNIQUE KEY uk_enrollments_token_id (host_token_id),
		INDEX idx_enrollments_prev_token (previous_host_token_id),
		INDEX idx_enrollments_tenant_id (tenant_id)
	)`,
}
