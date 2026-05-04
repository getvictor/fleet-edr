package bootstrap

import (
	"errors"

	"github.com/go-sql-driver/mysql"
)

// schemaStatements are the CREATE TABLE statements response owns.
// Idempotent (IF NOT EXISTS); safe to re-run on a populated DB. No
// FKs.
//
// Authoritative copy of the commands table DDL. Earlier server
// versions inlined this in server/store/store.go's applySchema; the
// bounded-context split moved it here.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS commands (
		id           BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id      VARCHAR(255)  NOT NULL,
		command_type VARCHAR(64)   NOT NULL,
		payload      JSON          NOT NULL,
		status       ENUM('pending', 'acked', 'completed', 'failed') NOT NULL DEFAULT 'pending',
		created_at   TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		acked_at     TIMESTAMP(6)  NULL,
		completed_at TIMESTAMP(6)  NULL,
		result       JSON,
		INDEX idx_commands_host_status (host_id, status),
		INDEX idx_commands_created (created_at)
	)`,
}

// schemaMigrations are idempotent ALTERs applied after the CREATE TABLEs.
// Errors that mean "already applied" are swallowed by
// isAlreadyAppliedMigration so re-running on a populated DB is a no-op.
var schemaMigrations = []string{
	// Tenant scaffolding (wave-1 user-management). The column exists for
	// future MSSP-style multi-tenancy; wave-1 reads do not filter on it.
	// VARCHAR(64) DEFAULT 'default' so the ALTER backfills existing rows
	// without a follow-up UPDATE.
	`ALTER TABLE commands ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'`,
}

// isAlreadyAppliedMigration returns true when err is one of the MySQL
// "this ALTER is already applied" codes, so we can treat the re-run as a
// no-op. Mirrors identity / endpoint bootstrap's helpers.
func isAlreadyAppliedMigration(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	// 1060 duplicate column, 1061 duplicate key name, 1826 duplicate FK name,
	// 1022 duplicate key on add (older code for FK name clash).
	switch mysqlErr.Number {
	case 1060, 1061, 1826, 1022:
		return true
	}
	return false
}
