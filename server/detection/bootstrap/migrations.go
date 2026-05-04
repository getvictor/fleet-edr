package bootstrap

import (
	"errors"
	"slices"

	"github.com/go-sql-driver/mysql"
)

// migrationStep is one idempotent ALTER. IgnoreErrors lists MySQL
// error codes that mean "already applied"; the bootstrap loop
// swallows them so re-running on an already-migrated DB is a no-op.
type migrationStep struct {
	Name         string
	SQL          string
	IgnoreErrors []uint16
}

// MySQL error codes the migration loop swallows on the
// "already-applied" path.
const (
	mysqlDuplicateColumn   = 1060 // 'col' already exists
	mysqlDuplicateKey      = 1061 // duplicate index name
	mysqlDuplicateKeyAlt   = 1022 // older code for duplicate-key on add
	mysqlDuplicateFKName   = 1826 // duplicate FK name
	mysqlCantDropFKMissing = 1091 // can't DROP X; check that column/key exists
	mysqlNoSuchFK          = 3940 // can't DROP FOREIGN KEY: doesn't have a FK named X
)

// migrations are idempotent ALTER TABLE statements applied after
// initial schema creation. Each statement preserves the migration
// history from earlier server versions (so existing-DB upgrades are
// wire-compatible) plus the FK drop on alerts.updated_by that the
// bounded-context migration introduced.
var migrations = []migrationStep{
	// Pre-bounded-context ALTERs preserved verbatim. Each is idempotent
	// via the duplicate-column / duplicate-key codes; the bootstrap
	// loop's IgnoreErrors swallows them on already-migrated DBs.
	{
		Name:         "events.processed",
		SQL:          `ALTER TABLE events ADD COLUMN processed TINYINT(1) NOT NULL DEFAULT 0`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "events.idx_processed",
		SQL:          `ALTER TABLE events ADD INDEX idx_events_processed (processed, host_id, timestamp_ns)`,
		IgnoreErrors: []uint16{mysqlDuplicateKey, mysqlDuplicateKeyAlt},
	},
	{
		Name:         "alerts.updated_by column",
		SQL:          `ALTER TABLE alerts ADD COLUMN updated_by BIGINT NULL`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "alerts.idx_updated_by",
		SQL:          `ALTER TABLE alerts ADD INDEX idx_alerts_updated_by (updated_by)`,
		IgnoreErrors: []uint16{mysqlDuplicateKey, mysqlDuplicateKeyAlt},
	},
	// Drop the cross-context FK alerts.updated_by -> users.id that
	// earlier server versions carried; detection enforces the integrity
	// check at the service layer instead (UserExists closure called
	// from UpdateAlertStatus). Ignores 1091/3940 so a fresh DB (no FK
	// to drop) and a re-run (FK already dropped) both succeed.
	{
		Name:         "drop fk_alerts_updated_by",
		SQL:          `ALTER TABLE alerts DROP FOREIGN KEY fk_alerts_updated_by`,
		IgnoreErrors: []uint16{mysqlCantDropFKMissing, mysqlNoSuchFK},
	},
	{
		Name:         "events.ingested_at_ns",
		SQL:          `ALTER TABLE events ADD COLUMN ingested_at_ns BIGINT NOT NULL DEFAULT 0`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "events.idx_host_type_ingested",
		SQL:          `ALTER TABLE events ADD INDEX idx_events_host_type_ingested (host_id, event_type, ingested_at_ns)`,
		IgnoreErrors: []uint16{mysqlDuplicateKey, mysqlDuplicateKeyAlt},
	},
	{
		Name:         "processes.fork_ingested_at_ns",
		SQL:          `ALTER TABLE processes ADD COLUMN fork_ingested_at_ns BIGINT NULL`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "processes.exit_ingested_at_ns",
		SQL:          `ALTER TABLE processes ADD COLUMN exit_ingested_at_ns BIGINT NULL`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "processes.exit_reason",
		SQL:          `ALTER TABLE processes ADD COLUMN exit_reason VARCHAR(32) NULL`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "alerts.techniques",
		SQL:          `ALTER TABLE alerts ADD COLUMN techniques JSON NULL`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "processes.previous_exec_id",
		SQL:          `ALTER TABLE processes ADD COLUMN previous_exec_id BIGINT NULL`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "processes.idx_previous_exec",
		SQL:          `ALTER TABLE processes ADD INDEX idx_processes_previous_exec (previous_exec_id)`,
		IgnoreErrors: []uint16{mysqlDuplicateKey, mysqlDuplicateKeyAlt},
	},
	// Tenant scaffolding (wave-1 user-management). The column exists for
	// future MSSP-style multi-tenancy; wave-1 reads do not filter on it.
	// VARCHAR(64) DEFAULT 'default' so an existing-DB ALTER backfills
	// every row to the seeded tenant without a follow-up UPDATE. Each
	// column is paired with an index so the wave-2 cutover does not
	// require a backfill migration on what are projected to be the
	// largest tables in the system.
	{
		Name:         "hosts.tenant_id",
		SQL:          `ALTER TABLE hosts ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "hosts.idx_tenant_id",
		SQL:          `ALTER TABLE hosts ADD INDEX idx_hosts_tenant_id (tenant_id)`,
		IgnoreErrors: []uint16{mysqlDuplicateKey, mysqlDuplicateKeyAlt},
	},
	{
		Name:         "alerts.tenant_id",
		SQL:          `ALTER TABLE alerts ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'`,
		IgnoreErrors: []uint16{mysqlDuplicateColumn},
	},
	{
		Name:         "alerts.idx_tenant_id",
		SQL:          `ALTER TABLE alerts ADD INDEX idx_alerts_tenant_id (tenant_id)`,
		IgnoreErrors: []uint16{mysqlDuplicateKey, mysqlDuplicateKeyAlt},
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
