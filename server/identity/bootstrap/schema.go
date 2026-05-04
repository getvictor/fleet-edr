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
}

// MySQL error numbers we treat as "already applied" for ALTER migrations.
// See https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html
const (
	mysqlErrDupFieldName = 1060 // duplicate column name
	mysqlErrDupKeyName   = 1061 // duplicate key name
	mysqlErrDupKey       = 1022 // duplicate key on add (older MySQL FK clash)
	mysqlErrFKDupName    = 1826 // duplicate FK constraint name
)

// isAlreadyAppliedMigration returns true when err is one of the MySQL
// "this ALTER is already applied" codes, so we can treat the re-run as a
// no-op.
func isAlreadyAppliedMigration(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	switch mysqlErr.Number {
	case mysqlErrDupFieldName, mysqlErrDupKeyName, mysqlErrFKDupName, mysqlErrDupKey:
		return true
	}
	return false
}
