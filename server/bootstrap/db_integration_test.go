//go:build integration

package bootstrap

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenDB_BoundsSharedConnectionPool_RealMySQL exercises the shipped OpenDB path end-to-end against a real MySQL and asserts the
// returned shared handle caps total open connections at the compiled ceiling, so processor-worker concurrency above that cap waits for a
// pooled connection instead of opening an unbounded number and exhausting MySQL's max_connections. This is the shipped-path counterpart
// to the lazy unit pin in db_test.go: it proves OpenDB itself applies the bound, not merely that a *sql.DB reflects a SetMaxOpenConns
// call, so a refactor that dropped the SetMaxOpenConns line would fail here.
//
// spec:server-availability/the-shared-database-connection-pool-is-bounded/worker-concurrency-cannot-exhaust-database-connections
func TestOpenDB_BoundsSharedConnectionPool_RealMySQL(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("EDR_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set")
	}

	db, err := OpenDB(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	assert.Equal(t, dbMaxOpenConns, db.Stats().MaxOpenConnections,
		"OpenDB must bound the shared pool to the compiled ceiling so worker concurrency cannot exhaust MySQL connections")
}
