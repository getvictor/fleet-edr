package leader

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	_ "github.com/go-sql-driver/mysql"
)

// TestKeepAliveRelinquishesOnPingFailure pins that the keep-alive relinquishes leadership when its ping fails (the lock
// connection dropped). A closed *sql.Conn makes PingContext fail, standing in for a connection that MySQL or the network closed
// out from under the leader. This is the branch that prevents a leader from running on after its lock is silently gone.
func TestKeepAliveRelinquishesOnPingFailure(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("EDR_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping leader keep-alive test")
	}
	db, err := sqlx.Open("mysql", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	conn, err := db.Conn(context.Background())
	require.NoError(t, err)
	require.NoError(t, conn.Close()) // a closed connection makes PingContext fail

	c := &mysqlCoordinator{db: db, keepAliveInterval: 10 * time.Millisecond, logger: slog.Default()}
	// A timeout backstops the call so a (wrong) succeeding ping can't hang the test; the real path returns when the ping fails.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var relinquished atomic.Bool
	c.keepAlive(ctx, func() { relinquished.Store(true) }, "test-lock", conn)
	require.True(t, relinquished.Load(), "keepAlive must relinquish the lease when the connection ping fails")
}
