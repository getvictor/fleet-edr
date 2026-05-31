package main

import (
	"io"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb"
)

func tableExists(t *testing.T, db *sqlx.DB, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`, name).Scan(&n))
	return n == 1
}

// TestApplyAll exercises the CLI's core: applying every context's migrations against a fresh database creates each context's
// tables, and a second pass is an idempotent no-op (goose skips already-applied versions). This is the smoke test that the
// standalone migrate path stays wired to all five contexts.
func TestApplyAll(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)

	require.NoError(t, applyAll(t.Context(), db, io.Discard))

	// One representative table per context, plus a per-context goose tracking table, must exist after the run.
	for _, table := range []string{
		"users", "enrollments", "app_control_policies", "commands", "events",
		"identity_goose_db_version", "endpoint_goose_db_version", "rules_goose_db_version",
		"response_goose_db_version", "detection_goose_db_version",
	} {
		assert.Truef(t, tableExists(t, db, table), "table %q must exist after applyAll", table)
	}

	// Re-running against the already-migrated DB must succeed without re-applying anything.
	require.NoError(t, applyAll(t.Context(), db, io.Discard))
}
