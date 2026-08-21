package leader_test

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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

// TestWithLock pins the mutual-exclusion contract WithLock backs the boot-time migration apply with: concurrent callers run fn one
// at a time (never overlapping), and every caller runs fn (unlike leader election, which abandons the work on the losers).
func TestWithLock(t *testing.T) {
	t.Parallel()

	t.Run("serializes concurrent callers and every caller runs fn", func(t *testing.T) {
		t.Parallel()
		a, _ := replicaDBs(t)
		coord := newCoord(a)
		name := uniqueLockName()
		const callers = 5

		var inCritical, maxConcurrent, ran atomic.Int64
		var wg sync.WaitGroup
		for range callers {
			wg.Go(func() {
				err := coord.WithLock(t.Context(), name, func(context.Context) error {
					cur := inCritical.Add(1)
					for { // record the high-water mark of simultaneous holders; a working lock keeps it at 1
						m := maxConcurrent.Load()
						if cur <= m || maxConcurrent.CompareAndSwap(m, cur) {
							break
						}
					}
					time.Sleep(10 * time.Millisecond) // widen the critical section so a broken lock would overlap and bump the mark
					ran.Add(1)
					inCritical.Add(-1)
					return nil
				})
				assert.NoError(t, err)
			})
		}
		wg.Wait()

		assert.Equal(t, int64(1), maxConcurrent.Load(), "WithLock must hold the lock exclusively: no two fns may overlap")
		assert.EqualValues(t, callers, ran.Load(), "every caller must run fn (mutual exclusion, not leader election)")
	})

	t.Run("returns fn's error", func(t *testing.T) {
		t.Parallel()
		a, _ := replicaDBs(t)
		sentinel := errors.New("boom")
		err := newCoord(a).WithLock(t.Context(), uniqueLockName(), func(context.Context) error { return sentinel })
		require.ErrorIs(t, err, sentinel)
	})

	t.Run("blocks while another session holds the lock, then acquires on release", func(t *testing.T) {
		t.Parallel()
		a, b := replicaDBs(t)
		name := uniqueLockName()

		// Hold the lock from an independent session (a stand-in for another replica).
		holder, err := b.Connx(t.Context())
		require.NoError(t, err)
		defer func() { _ = holder.Close() }()
		var got sql.NullInt64
		require.NoError(t, holder.QueryRowContext(t.Context(), "SELECT GET_LOCK(?, 0)", name).Scan(&got))
		require.EqualValues(t, 1, got.Int64, "the holder should acquire the free lock")

		ran := make(chan struct{})
		go func() {
			_ = newCoord(a).WithLock(t.Context(), name, func(context.Context) error {
				close(ran)
				return nil
			})
		}()
		// WithLock must block while the holder keeps the lock.
		select {
		case <-ran:
			t.Fatal("WithLock acquired while another session held the lock")
		case <-time.After(200 * time.Millisecond):
		}
		// Release from the holder; WithLock's blocking GET_LOCK then acquires and runs fn.
		_, err = holder.ExecContext(t.Context(), "SELECT RELEASE_LOCK(?)", name)
		require.NoError(t, err)
		select {
		case <-ran:
		case <-time.After(3 * time.Second):
			t.Fatal("WithLock did not acquire after the holder released the lock")
		}
	})

	t.Run("returns the context error when cancelled while waiting", func(t *testing.T) {
		t.Parallel()
		a, b := replicaDBs(t)
		name := uniqueLockName()

		holder, err := b.Connx(t.Context())
		require.NoError(t, err)
		defer func() { _ = holder.Close() }()
		var got sql.NullInt64
		require.NoError(t, holder.QueryRowContext(t.Context(), "SELECT GET_LOCK(?, 0)", name).Scan(&got))
		require.EqualValues(t, 1, got.Int64)

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		var fnRan atomic.Bool
		err = newCoord(a).WithLock(ctx, name, func(context.Context) error {
			fnRan.Store(true)
			return nil
		})
		require.ErrorIs(t, err, context.DeadlineExceeded, "WithLock must return ctx's error when cancelled before acquiring")
		require.False(t, fnRan.Load(), "fn must not run when the lock was never acquired")
	})

	t.Run("surfaces the acquire error on a closed pool", func(t *testing.T) {
		t.Parallel()
		a, _ := replicaDBs(t)
		require.NoError(t, a.Close()) // a closed pool makes the lock-connection open fail
		var fnRan atomic.Bool
		err := newCoord(a).WithLock(t.Context(), uniqueLockName(), func(context.Context) error {
			fnRan.Store(true)
			return nil
		})
		require.Error(t, err)
		require.False(t, fnRan.Load(), "fn must not run when the lock could not be acquired")
	})
}

// TestLockSurvivesAnIdleConnectionClose is the regression test for issue #721: the one-shot and scoped lock forms held the lock on a
// connection that sat IDLE for the whole callback, because the callback does its work on a different pooled connection. Nothing kept
// that connection warm, so MySQL closing it (wait_timeout, a proxy, an operator KILL) released the lock silently and let a second
// caller into a section that is supposed to be exclusive.
//
// The old failure was invisible by construction: the callback ran to completion and reported success, having lost its exclusivity
// partway through. So the test asserts the reporting, not just the survival. It kills exactly the connection holding the lock,
// resolved through IS_USED_LOCK rather than by killing anything broader, which is precisely the event wait_timeout would produce.
//
//nolint:tparallel // The subtests must NOT be parallel; see the comment on the pool budget below.
func TestLockSurvivesAnIdleConnectionClose(t *testing.T) {
	t.Parallel()
	db, _ := replicaDBs(t)
	// A keep-alive far shorter than the test's own deadline, so the ping lands inside the callback rather than after it.
	coord := leader.NewMySQL(db, slog.Default(), leader.WithKeepAliveInterval(10*time.Millisecond))

	killLockHolder := func(t *testing.T, ctx context.Context, lockName string) { //nolint:revive // ctx after t reads better here
		t.Helper()
		var holder sql.NullInt64
		require.NoError(t, db.GetContext(ctx, &holder, "SELECT IS_USED_LOCK(?)", lockName))
		require.True(t, holder.Valid, "the lock must be held for this test to be killing the right connection")
		// KILL takes no placeholders, and holder.Int64 is an int64 the server itself just returned, so there is nothing to inject.
		// It is asynchronous and racing the keep-alive's own ping, so the error is advisory: the assertions are on the reported
		// outcome, not on this statement.
		_, _ = db.ExecContext(ctx, fmt.Sprintf("KILL %d", holder.Int64)) //nolint:gosec // int64 from the server, not user input
	}

	// The subtests deliberately do NOT run in parallel with each other. replicaDBs caps the pool at 3 connections, and each subtest
	// pins one for the whole callback (the lock connection) and then needs a second inside it (the IS_USED_LOCK lookup and the KILL).
	// Four in parallel exhaust the pool and every callback blocks forever waiting for a connection that only another callback can
	// free, which is the same shape as issue #722 and cost 10 minutes of wall clock to diagnose the first time.
	t.Run("spec:server-availability/an-advisory-lock-is-held-for-as-long-as-its-holder-runs/a-lock-lost-mid-callback-is-reported-not-absorbed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		lockName := uniqueLockName()

		ran, err := coord.DoOnceIfLeader(ctx, lockName, func(fnCtx context.Context) error {
			killLockHolder(t, ctx, lockName)
			<-fnCtx.Done() // the keep-alive notices the dead connection and cancels the lease
			return nil
		})

		assert.True(t, ran, "this replica did win the lock, so it did run")
		require.ErrorIs(t, err, leader.ErrLockLost,
			"returning nil here is the bug: the callback ran, but not under the exclusion it asked for")
	})

	t.Run("WithLock reports a lock it lost mid-callback", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		lockName := uniqueLockName()

		err := coord.WithLock(ctx, lockName, func(fnCtx context.Context) error {
			killLockHolder(t, ctx, lockName)
			<-fnCtx.Done()
			return nil
		})

		require.ErrorIs(t, err, leader.ErrLockLost)
	})

	t.Run("spec:server-availability/an-advisory-lock-is-held-for-as-long-as-its-holder-runs/a-lock-outlives-the-closing-of-its-idle-connection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Long enough for several keep-alive ticks, so a keep-alive that wrongly reported loss on a HEALTHY connection would be
		// caught here rather than only on the kill path above.
		err := coord.WithLock(ctx, uniqueLockName(), func(context.Context) error {
			time.Sleep(100 * time.Millisecond)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("spec:server-availability/an-advisory-lock-is-held-for-as-long-as-its-holder-runs/the-callback-s-own-failure-is-not-masked-by-the-lock-loss", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		lockName := uniqueLockName()
		sentinel := errors.New("callback failed on its own terms")

		err := coord.WithLock(ctx, lockName, func(fnCtx context.Context) error {
			killLockHolder(t, ctx, lockName)
			<-fnCtx.Done()
			return sentinel
		})
		require.ErrorIs(t, err, sentinel, "the callback's diagnosis is more specific than ErrLockLost and must win")
	})
}

// TestLockGrantsExclusionAndReleases covers the bare Lock form, which had no test at all before issue #721 added a keep-alive to it.
//
// It is the one lock form that cannot abort its caller when the lock is lost, because there is no callback context to cancel, so
// what it can be held to is narrower: it must actually exclude, its release must actually free the lock, and the keep-alive it now
// runs must not interfere with either.
func TestLockGrantsExclusionAndReleases(t *testing.T) {
	t.Parallel()
	dbA, dbB := replicaDBs(t)
	// Keep-alive well inside the test's own lifetime, so the ping fires while the lock is held rather than after it is released.
	coordA := leader.NewMySQL(dbA, slog.Default(), leader.WithKeepAliveInterval(10*time.Millisecond))
	coordB := leader.NewMySQL(dbB, slog.Default(), leader.WithKeepAliveInterval(10*time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lockName := uniqueLockName()

	release, err := coordA.Lock(ctx, lockName)
	require.NoError(t, err)

	// Held long enough for several keep-alive ticks, so a keep-alive that broke the lock (by relinquishing on a healthy
	// connection, say) would show up as the second replica getting in.
	time.Sleep(100 * time.Millisecond)

	secondAcquired := make(chan struct{})
	go func() {
		r, lerr := coordB.Lock(ctx, lockName)
		if lerr == nil {
			r()
			close(secondAcquired)
		}
	}()
	select {
	case <-secondAcquired:
		t.Fatal("a second replica acquired a lock the first still holds")
	case <-time.After(200 * time.Millisecond):
	}

	release()

	select {
	case <-secondAcquired:
	case <-time.After(10 * time.Second):
		t.Fatal("release did not free the lock; the second replica never acquired it")
	}
}

// TestLockReleaseIsIdempotentUnderCancelledContext pins that a lock taken on a context that is later cancelled still frees on
// release. The boot sequence is the caller here, and a shutdown racing the migration lock must not leave it held for the next
// replica to block on: release runs on a cancellation-stripped context precisely so this holds.
func TestLockReleaseIsIdempotentUnderCancelledContext(t *testing.T) {
	t.Parallel()
	db, _ := replicaDBs(t)
	coord := leader.NewMySQL(db, slog.Default(), leader.WithKeepAliveInterval(10*time.Millisecond))
	lockName := uniqueLockName()

	ctx, cancel := context.WithCancel(context.Background())
	release, err := coord.Lock(ctx, lockName)
	require.NoError(t, err)

	cancel() // the shutdown arrives while the lock is held
	release()

	// The lock must be free: a fresh acquire on an uncancelled context succeeds immediately.
	freshCtx, freshCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer freshCancel()
	again, err := coord.Lock(freshCtx, lockName)
	require.NoError(t, err, "a lock released after its context was cancelled must still be free")
	again()
}
