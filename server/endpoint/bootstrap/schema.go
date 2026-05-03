package bootstrap

import (
	"errors"

	"github.com/go-sql-driver/mysql"
)

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
		enrolled_at                TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		expires_at                 TIMESTAMP(6)   NULL,
		revoked_at                 TIMESTAMP(6)   NULL,
		revoke_reason              VARCHAR(128)   NULL,
		revoked_by                 VARCHAR(255)   NULL,
		UNIQUE KEY uk_enrollments_token_id (host_token_id),
		INDEX idx_enrollments_prev_token (previous_host_token_id)
	)`,
}

// schemaMigrations are idempotent ALTERs applied after the CREATE TABLEs
// for upgrading databases that were created before the rotation columns
// existed. Errors that mean "already applied" (duplicate column,
// duplicate key) are swallowed by isAlreadyAppliedMigration so re-running
// on a populated DB is a no-op.
//
// On a fresh DB the CREATE TABLE above already includes every column +
// index this list adds, so every statement here returns "already applied"
// and the loop is a no-op. The list exists for the upgrade path: an
// operator running an older binary against the same MySQL gets the
// rotation columns added in place.
var schemaMigrations = []string{
	`ALTER TABLE enrollments ADD COLUMN host_token_issued_at TIMESTAMP(6) NULL`,
	// Backfill existing rows from enrolled_at so any host older than the
	// rotation interval is flagged "rotation due" on its next verify, per
	// #86's deploy contract. Idempotent: WHERE host_token_issued_at IS NULL
	// excludes rows that already ran through this migration, and excludes
	// rows born after the column went NOT NULL.
	`UPDATE enrollments SET host_token_issued_at = enrolled_at WHERE host_token_issued_at IS NULL`,
	`ALTER TABLE enrollments MODIFY COLUMN host_token_issued_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)`,
	`ALTER TABLE enrollments ADD COLUMN previous_host_token_id    VARBINARY(32)  NULL`,
	`ALTER TABLE enrollments ADD COLUMN previous_host_token_hash  VARBINARY(255) NULL`,
	`ALTER TABLE enrollments ADD COLUMN previous_host_token_salt  VARBINARY(32)  NULL`,
	`ALTER TABLE enrollments ADD COLUMN previous_token_expires_at TIMESTAMP(6)   NULL`,
	`ALTER TABLE enrollments ADD INDEX idx_enrollments_prev_token (previous_host_token_id)`,
}

// isAlreadyAppliedMigration returns true when err is one of the MySQL
// "this ALTER is already applied" codes, so we can treat the re-run as a
// no-op. Mirrors identity/bootstrap's helper.
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
