package bootstrap

import (
	"errors"
	"slices"

	"github.com/go-sql-driver/mysql"
)

// migrationStep is one idempotent ALTER. IgnoreErrors lists MySQL
// error codes that mean "already applied"; the bootstrap loop
// swallows them so re-running on an already-migrated DB is a no-op.
// Mirrors detection/bootstrap/migrations.go - kept locally rather
// than centralized so each context owns its migration history.
type migrationStep struct {
	Name         string
	SQL          string
	IgnoreErrors []uint16
}

// MySQL error codes the migration loop swallows on the
// "already-applied" path.
const (
	mysqlDuplicateColumn = 1060 // 'col' already exists
	mysqlDuplicateKey    = 1061 // duplicate index name
	mysqlDuplicateKeyAlt = 1022 // older code for duplicate-key on add
)

// migrations are idempotent ALTER TABLE statements applied after the
// CREATE TABLE statements. The identity schema documents that
// pre-release iteration accumulates additive changes inline rather
// than as separate ALTERs - but a wave-1 QA pass against a populated
// dev DB still needs an upgrade path, and this list provides it.
// Each migration is also present in the inline CREATE TABLE above,
// so a fresh deployment sees the migration as a no-op (duplicate
// column / duplicate key swallowed) and the loop becomes a free
// schema-drift check.
var migrations = []migrationStep{
	// WebAuthn BackupEligible / BackupState flags. Without these
	// columns the credential row's flags default to 0 on read, the
	// library compares against the asserted flags (1 for any
	// platform-authenticator-with-sync Passkey), and rejects with
	// "Backup Eligible flag inconsistency detected during login
	// validation." Persisting BE + BS unblocks every iCloud
	// Keychain / Google Password Manager / Windows Hello synced
	// credential.
	{
		Name:         "webauthn_credentials.backup_eligible",
		SQL:          `ALTER TABLE webauthn_credentials ADD COLUMN backup_eligible TINYINT(1) NOT NULL DEFAULT 0`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "webauthn_credentials.backup_state",
		SQL:          `ALTER TABLE webauthn_credentials ADD COLUMN backup_state TINYINT(1) NOT NULL DEFAULT 0`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
}

// shouldIgnore reports whether err matches any of the codes in the
// step's IgnoreErrors list.
func (m migrationStep) shouldIgnore(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return slices.Contains(m.IgnoreErrors, mysqlErr.Number)
}
