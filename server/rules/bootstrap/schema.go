package bootstrap

import (
	"errors"

	"github.com/go-sql-driver/mysql"
)

// schemaStatements are the CREATE TABLE + seed statements rules owns.
// Idempotent (IF NOT EXISTS / INSERT IGNORE); safe to re-run on a
// populated DB. No cross-context FKs.
//
// Authoritative copy of the policies table DDL. Earlier server
// versions inlined this in server/store/store.go's applySchema; the
// bounded-context split moved it here.
var schemaStatements = []string{
	// policies holds the server-driven blocklist. For MVP we keep a
	// single "default" row -- `name` is a UNIQUE key so v1.1 can add
	// per-team targeting without a schema migration. `version` is a
	// monotonically-increasing integer bumped on every admin PUT;
	// agents cache the last-applied version and skip no-op updates.
	`CREATE TABLE IF NOT EXISTS policies (
		id          BIGINT AUTO_INCREMENT PRIMARY KEY,
		name        VARCHAR(64)  NOT NULL,
		version     BIGINT       NOT NULL DEFAULT 1,
		blocklist   JSON         NOT NULL,
		updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_by  VARCHAR(255) NOT NULL DEFAULT 'system',
		UNIQUE KEY uk_policies_name (name)
	)`,
	// Seed the default policy row. Using INSERT IGNORE so restarts
	// don't clobber an edited row. The initial blocklist is empty --
	// operators opt in to blocking via PUT.
	`INSERT IGNORE INTO policies (name, version, blocklist, updated_by)
	 VALUES ('default', 1, JSON_OBJECT('paths', JSON_ARRAY(), 'hashes', JSON_ARRAY()), 'system')`,
}

// schemaMigrations are idempotent ALTERs applied after the CREATE TABLEs.
// Errors that mean "already applied" are swallowed by
// isAlreadyAppliedMigration so re-running on a populated DB is a no-op.
var schemaMigrations = []string{
	// Tenant scaffolding (wave-1 user-management). The column exists for
	// future MSSP-style multi-tenancy; wave-1 reads do not filter on it.
	// VARCHAR(64) DEFAULT 'default' so the ALTER backfills existing rows
	// without a follow-up UPDATE. Paired with an index so the wave-2
	// cutover does not need a backfill migration.
	`ALTER TABLE policies ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'`,
	`ALTER TABLE policies ADD INDEX idx_policies_tenant_id (tenant_id)`,
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
