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
	`CREATE TABLE IF NOT EXISTS enrollments (
		host_id          VARCHAR(255) PRIMARY KEY,
		host_token_id    VARBINARY(32)  NOT NULL,
		host_token_hash  VARBINARY(255) NOT NULL,
		host_token_salt  VARBINARY(32)  NOT NULL,
		hostname         VARCHAR(255)   NOT NULL,
		agent_version    VARCHAR(64)    NOT NULL,
		os_version       VARCHAR(128)   NOT NULL,
		source_ip        VARCHAR(45)    NOT NULL,
		enrolled_at      TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		expires_at       TIMESTAMP(6)   NULL,
		revoked_at       TIMESTAMP(6)   NULL,
		revoke_reason    VARCHAR(128)   NULL,
		revoked_by       VARCHAR(255)   NULL,
		UNIQUE KEY uk_enrollments_token_id (host_token_id)
	)`,
}
