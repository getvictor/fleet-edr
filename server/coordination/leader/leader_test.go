package leader_test

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/go-sql-driver/mysql"

	"github.com/fleetdm/edr/server/coordination/leader"
)

// lockSalt makes lock names unique per test process so parallel packages sharing one MySQL server (GET_LOCK names are
// server-global) don't collide, and so they never clash with the production names (edr_retention, edr_process_ttl).
var lockSalt = func() string {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}()

var lockSeq atomic.Int64

func uniqueLockName() string { return fmt.Sprintf("edrtest_%s_%d", lockSalt, lockSeq.Add(1)) }

// replicaDBs opens two independent MySQL handles to the test server, simulating two replicas (each its own connection pool, hence
// its own GET_LOCK sessions). GET_LOCK needs no schema, so the test connects via EDR_TEST_DSN directly and skips when it is unset.
func replicaDBs(t *testing.T) (*sqlx.DB, *sqlx.DB) {
	t.Helper()
	dsn := os.Getenv("EDR_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping leader integration test")
	}
	open := func() *sqlx.DB {
		db, err := sqlx.Open("mysql", dsn)
		require.NoError(t, err)
		db.SetMaxOpenConns(3) // a held lock connection plus headroom for poll attempts + the killer query
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return open(), open()
}

func newCoord(db *sqlx.DB) leader.Coordinator {
	return leader.NewMySQL(db, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		leader.WithPollInterval(20*time.Millisecond))
}

// runLeader starts coord.RunIfLeader in a goroutine; the fn closes `ran` when it becomes leader and then blocks until ctx is
// cancelled (the shape of a real periodic loop).
func runLeader(ctx context.Context, coord leader.Coordinator, name string) <-chan struct{} {
	ran := make(chan struct{})
	go func() {
		_ = coord.RunIfLeader(ctx, name, func(ctx context.Context) error {
			close(ran)
			<-ctx.Done()
			return nil
		})
	}()
	return ran
}

func TestRunIfLeader(t *testing.T) {
	t.Parallel()

	t.Run("spec:server-availability/periodic-tasks-run-on-exactly-one-replica-via-mysql-advisory-locking/single-replica-acquires-the-lease-uncontended", func(t *testing.T) {
		t.Parallel()
		a, _ := replicaDBs(t)
		ran := runLeader(t.Context(), newCoord(a), uniqueLockName())
		select {
		case <-ran:
		case <-time.After(3 * time.Second):
			t.Fatal("uncontended replica never acquired leadership")
		}
	})

	t.Run("spec:server-availability/periodic-tasks-run-on-exactly-one-replica-via-mysql-advisory-locking/concurrent-replicas-elect-exactly-one-leader-per-task", func(t *testing.T) {
		t.Parallel()
		a, b := replicaDBs(t)
		name := uniqueLockName()
		ctx := t.Context()

		var leaders atomic.Int64
		fn := func(ctx context.Context) error {
			leaders.Add(1)
			<-ctx.Done()
			return nil
		}
		go func() { _ = newCoord(a).RunIfLeader(ctx, name, fn) }()
		go func() { _ = newCoord(b).RunIfLeader(ctx, name, fn) }()

		require.Eventually(t, func() bool { return leaders.Load() == 1 }, 3*time.Second, 20*time.Millisecond,
			"exactly one replica should hold leadership")
		// Hold a while longer: the follower keeps polling but must never also become leader while the first holds the lock.
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, int64(1), leaders.Load(), "the follower must not also acquire while the leader holds the lock")
	})

	t.Run("spec:server-availability/periodic-tasks-run-on-exactly-one-replica-via-mysql-advisory-locking/lease-releases-on-context-cancel", func(t *testing.T) {
		t.Parallel()
		a, b := replicaDBs(t)
		name := uniqueLockName()

		ctxA, cancelA := context.WithCancel(t.Context())
		defer cancelA()
		aRan := runLeader(ctxA, newCoord(a), name)
		<-aRan // A is leader

		bRan := runLeader(t.Context(), newCoord(b), name)
		select {
		case <-bRan:
			t.Fatal("B acquired while A still held the lock")
		case <-time.After(200 * time.Millisecond): // B correctly blocked
		}

		cancelA() // A releases the lock on cancel
		select {
		case <-bRan: // B took over
		case <-time.After(3 * time.Second):
			t.Fatal("B did not acquire after A released the lock on context cancel")
		}
	})

	t.Run("spec:server-availability/periodic-tasks-run-on-exactly-one-replica-via-mysql-advisory-locking/lease-releases-on-replica-crash-via-connection-close", func(t *testing.T) {
		t.Parallel()
		a, b := replicaDBs(t)
		name := uniqueLockName()
		ctx := t.Context()

		// Replica A holds the lock on a dedicated connection (the coordinator's design); record its MySQL connection id.
		connA, err := a.Conn(ctx)
		require.NoError(t, err)
		var got sql.NullInt64
		require.NoError(t, connA.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", name).Scan(&got))
		require.EqualValues(t, 1, got.Int64, "A should acquire the free lock")
		var connID int64
		require.NoError(t, connA.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&connID))

		// While A holds it, another replica cannot acquire.
		require.NoError(t, b.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", name).Scan(&got))
		require.EqualValues(t, 0, got.Int64, "B must not acquire while A holds the lock")

		// Simulate A's process crashing: kill its connection. MySQL releases a session's locks when its connection drops, which
		// is what makes coordinator leadership crash-safe without an explicit lease TTL.
		_, _ = b.ExecContext(ctx, fmt.Sprintf("KILL CONNECTION %d", connID)) //nolint:gosec // connID is a MySQL CONNECTION_ID(), not user input
		_ = connA.Close()

		require.Eventually(t, func() bool {
			conn, e := b.Conn(ctx)
			if e != nil {
				return false
			}
			defer func() { _ = conn.Close() }()
			var g sql.NullInt64
			if conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", name).Scan(&g) != nil {
				return false
			}
			if g.Valid && g.Int64 == 1 {
				_, _ = conn.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", name)
				return true
			}
			return false
		}, 5*time.Second, 50*time.Millisecond, "lock not released after the holding connection was killed")
	})

	t.Run("re-acquires leadership after losing the lease without shutdown", func(t *testing.T) {
		t.Parallel()
		a, _ := replicaDBs(t)
		coord := newCoord(a)
		name := uniqueLockName()
		ctx := t.Context()

		var calls atomic.Int64
		go func() {
			_ = coord.RunIfLeader(ctx, name, func(fnCtx context.Context) error {
				if calls.Add(1) == 1 {
					return nil // simulate a lost lease: fn returns while the parent ctx is still alive
				}
				<-fnCtx.Done() // later acquisitions hold leadership normally
				return nil
			})
		}()
		// After the first fn returns without the parent cancelling, RunIfLeader must re-acquire and call fn again rather than
		// abandoning leadership.
		require.Eventually(t, func() bool { return calls.Load() >= 2 }, 3*time.Second, 20*time.Millisecond,
			"RunIfLeader should re-acquire after losing the lease")
	})

	t.Run("acquire error retries until context cancel", func(t *testing.T) {
		t.Parallel()
		a, _ := replicaDBs(t)
		require.NoError(t, a.Close()) // a closed pool makes every acquire attempt error

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		coord := newCoord(a)
		// RunIfLeader must keep hitting the acquire-error path and then return nil (graceful) when ctx expires, not hang.
		require.NoError(t, coord.RunIfLeader(ctx, uniqueLockName(), func(context.Context) error { return nil }))
		// DoOnceIfLeader surfaces the acquire error to the caller (which fails open). Use a fresh context so the error is the
		// closed pool, not the already-expired timeout context above.
		ran, err := coord.DoOnceIfLeader(context.Background(), uniqueLockName(), func(context.Context) error { return nil })
		require.Error(t, err)
		require.False(t, ran)
	})
}

// TestDoOnceIfLeader pins that across replicas racing the same one-shot lock, fn runs on exactly one of them and the losers skip
// without running it. This is the mechanism that makes the break-glass redemption banner print exactly once across a concurrent
// cluster boot (cmd/main gates the banner emission on this); fn here stands in for "emit the banner".
func TestDoOnceIfLeader(t *testing.T) {
	t.Parallel()
	t.Run("spec:server-availability/first-boot-admin-seed-is-safe-under-concurrent-replica-boot/only-one-replica-emits-the-bootstrap-token-banner-under-concurrent-boot", func(t *testing.T) {
		t.Parallel()
		const replicas = 6
		a, _ := replicaDBs(t)
		a.SetMaxOpenConns(replicas + 2) // each concurrent attempt grabs its own connection (its own GET_LOCK session)
		coord := newCoord(a)
		name := uniqueLockName()

		var emits atomic.Int64
		start := make(chan struct{})
		hold := make(chan struct{})
		var wg sync.WaitGroup
		for range replicas {
			wg.Go(func() {
				<-start // release all attempts together to maximise contention
				_, _ = coord.DoOnceIfLeader(t.Context(), name, func(context.Context) error {
					emits.Add(1)
					<-hold // the winner holds the lock until every loser has made its single attempt
					return nil
				})
			})
		}
		close(start)
		// Every replica makes its one non-blocking attempt within microseconds of the barrier; the winner is still holding, so
		// the losers all see the lock taken. A generous wait removes any timing flake before the assertion.
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, int64(1), emits.Load(), "exactly one replica should emit; the losers must not")
		close(hold)
		wg.Wait()
		assert.Equal(t, int64(1), emits.Load(), "no replica should emit after the winner releases")
	})
}
