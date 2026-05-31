package runner_test

import (
	"context"
	"embed"
	"io/fs"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/testdb"
)

// testMigrations is a minimal one-file corpus used to exercise the runner independently of any bounded context's real schema. It
// mirrors the production shape exactly: an embed.FS whose root holds NNNNN_name.sql files, the same as a context's
// `//go:embed *.sql`.
//
//go:embed testdata/migrations/*.sql
var testMigrations embed.FS

// testTable is this test's goose tracking table. A dedicated name keeps the runner test's bookkeeping from colliding with any
// real context tracking table if both ever land in the same database.
const testTable = "runner_test_goose_db_version"

func migrationsFS(t *testing.T) fs.FS {
	t.Helper()
	sub, err := fs.Sub(testMigrations, "testdata/migrations")
	require.NoError(t, err)
	return sub
}

func count(t *testing.T, db *sqlx.DB, query string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), query).Scan(&n))
	return n
}

func tableExists(t *testing.T, db *sqlx.DB, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`, name).Scan(&n))
	return n == 1
}

func TestUp(t *testing.T) {
	t.Parallel()

	t.Run("spec:server-availability/schema-is-managed-by-versioned-forward-only-per-context-migrations/applying-a-baseline-on-a-fresh-database-creates-its-tables", func(t *testing.T) {
		t.Parallel()
		db := testdb.Open(t)

		require.NoError(t, runner.Up(t.Context(), db, migrationsFS(t),
			runner.Options{Context: "runnertest", TableName: testTable}))

		assert.True(t, tableExists(t, db, "widgets"), "the corpus' table must exist after apply")
		assert.True(t, tableExists(t, db, testTable), "the per-context tracking table must be created")
		assert.GreaterOrEqual(t, count(t, db, `SELECT COUNT(*) FROM `+testTable+` WHERE version_id = 1`), 1,
			"the tracking table must record the applied version")
	})

	t.Run("spec:server-availability/schema-is-managed-by-versioned-forward-only-per-context-migrations/re-applying-an-already-applied-corpus-makes-no-changes", func(t *testing.T) {
		t.Parallel()
		db := testdb.Open(t)
		opts := runner.Options{Context: "runnertest", TableName: testTable}

		require.NoError(t, runner.Up(t.Context(), db, migrationsFS(t), opts))
		before := count(t, db, `SELECT COUNT(*) FROM `+testTable)

		// Second apply against an already-migrated database must succeed and must not record a new version. This is the property
		// the boot path and the existing "second ApplySchema re-apply succeeds" context tests rely on.
		require.NoError(t, runner.Up(t.Context(), db, migrationsFS(t), opts))
		after := count(t, db, `SELECT COUNT(*) FROM `+testTable)

		assert.Equal(t, before, after, "re-applying an already-applied corpus must not change the tracking table")
	})

	t.Run("nil db is rejected", func(t *testing.T) {
		t.Parallel()
		err := runner.Up(context.Background(), nil, migrationsFS(t),
			runner.Options{Context: "runnertest", TableName: testTable})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "db must not be nil")
	})

	t.Run("nil db.DB is rejected", func(t *testing.T) {
		t.Parallel()
		// A zero-value sqlx.DB is non-nil but its underlying *sql.DB is nil; goose would panic on it.
		err := runner.Up(context.Background(), &sqlx.DB{}, migrationsFS(t),
			runner.Options{Context: "runnertest", TableName: testTable})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "db must not be nil")
	})

	t.Run("nil fsys is rejected", func(t *testing.T) {
		t.Parallel()
		db := testdb.Open(t)
		err := runner.Up(t.Context(), db, nil,
			runner.Options{Context: "runnertest", TableName: testTable})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fsys must not be nil")
	})

	t.Run("empty context is rejected", func(t *testing.T) {
		t.Parallel()
		err := runner.Up(context.Background(), nil, migrationsFS(t),
			runner.Options{TableName: testTable})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context name must not be empty")
	})

	t.Run("empty table name is rejected", func(t *testing.T) {
		t.Parallel()
		db := testdb.Open(t)
		err := runner.Up(t.Context(), db, migrationsFS(t), runner.Options{Context: "runnertest"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "table name must not be empty")
	})
}
