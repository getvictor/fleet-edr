// Package leader coordinates "run this on exactly one replica" work across a multi-replica deployment using MySQL named advisory
// locks (GET_LOCK / RELEASE_LOCK).
//
// It backs the server-availability requirement that periodic maintenance tasks (event retention, the stale-process TTL
// reconciler) run on a single replica even though every replica boots the same binary. The event processor is deliberately NOT
// coordinated this way: it scales across replicas via SELECT ... FOR UPDATE SKIP LOCKED, so each replica claims disjoint batches.
//
// A lock is held for the lifetime of a dedicated *sql.Conn. That makes leadership crash-safe for free: when a leader process dies
// its connection drops, and MySQL releases the session's locks, so a waiting replica acquires on its next poll. Graceful shutdown
// releases the lock explicitly. See docs/adr/0010-stateless-server.md and openspec/specs/server-availability/spec.md.
//
// The package also provides WithLock, a blocking mutual-exclusion primitive (every caller runs the work, serialized) distinct from
// the leader-election helpers above. It backs the boot-time migration sequence: under a rolling upgrade several replicas may boot
// concurrently, and the advisory lock serializes their schema apply so no two run goose Up against the same database at once.
package leader

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/jmoiron/sqlx"
)

// defaultPollInterval is how often a non-leader replica re-attempts to acquire the lock. It bounds failover latency: when the
// current leader exits or crashes, a waiting replica takes over within roughly this interval. Retention + process-TTL are not
// latency-sensitive, so a relaxed interval keeps the GET_LOCK polling cost negligible.
const defaultPollInterval = 15 * time.Second

// defaultKeepAliveInterval is how often the leader pings its lock connection. The leader callback is a long-lived loop, so without
// pings the lock connection would sit idle for the whole run and MySQL would eventually close it as idle (wait_timeout), silently
// releasing the lock and admitting a second leader. A minute is well under MySQL's 8h default and most tightened values.
const defaultKeepAliveInterval = 1 * time.Minute

// lockWaitSeconds is the GET_LOCK timeout. 0 means non-blocking: GET_LOCK returns immediately (1 if free, 0 if held by another
// session). The scheduler retries every poll interval, so blocking inside GET_LOCK would only duplicate that wait.
const lockWaitSeconds = 0

// lockAcquireWaitSeconds bounds a single blocking GET_LOCK attempt inside the Lock acquire loop. The loop re-runs, so this only caps
// how long one attempt blocks server-side before the loop re-checks ctx; a cancelled ctx also interrupts the in-flight GET_LOCK via
// the query context. It is long enough to usually acquire in a single attempt yet short enough that boot does not hang unbounded if
// the driver fails to propagate a cancel into a blocked GET_LOCK.
const lockAcquireWaitSeconds = 10

// releaseTimeout bounds the RELEASE_LOCK + connection close on the deferred release path. release runs on a cancellation-stripped
// context (so the lock is still freed during a graceful shutdown), which otherwise has no deadline; without this cap a hung or
// unresponsive database could block shutdown — or a WithLock/Lock caller's deferred release — indefinitely.
const releaseTimeout = 5 * time.Second

// Coordinator runs work on exactly one replica at a time.
type Coordinator interface {
	// RunIfLeader runs fn on exactly one replica at a time, identified by lockName. It acquires the lock, runs fn while holding
	// it, and releases when fn returns or ctx is cancelled. Replicas that do not hold the lock poll for it at the coordinator's
	// interval, so when the current leader exits or crashes (its connection drops, freeing the lock) a waiting replica takes
	// over. Returns nil on graceful (ctx-cancelled) shutdown, or fn's error if fn returns one on the leader.
	RunIfLeader(ctx context.Context, lockName string, fn func(context.Context) error) error

	// DoOnceIfLeader makes a single non-blocking attempt to acquire lockName and, if it wins, runs fn once while holding the lock
	// and then releases. It returns (true, fnErr) when this replica ran fn, or (false, nil) when another replica currently holds
	// the lock. Unlike RunIfLeader it never waits or retries: a replica that loses the race simply reports false. It is for
	// boot-time one-shots, like printing the break-glass redemption banner exactly once across a concurrent cluster boot, where
	// blocking to become leader would hang startup.
	DoOnceIfLeader(ctx context.Context, lockName string, fn func(context.Context) error) (bool, error)

	// WithLock runs fn while holding lockName, blocking until the lock is acquired or ctx is cancelled. Unlike RunIfLeader (which
	// elects one replica and abandons the work on the others), every caller of WithLock runs fn: it is mutual exclusion, not leader
	// election. It backs the boot-time migration sequence, where every replica must apply migrations (goose makes an
	// already-applied corpus a no-op) but no two replicas may run goose Up against the same database concurrently. Returns ctx's
	// error if cancelled before the lock is acquired, otherwise fn's error.
	//
	// WithLock is for SHORT critical sections. Unlike RunIfLeader it does NOT ping the lock connection, so fn must finish well
	// within MySQL's wait_timeout; otherwise the idle lock connection could be closed and the lock silently released mid-fn. The
	// boot-time schema apply (milliseconds to a few seconds) fits comfortably; long-lived single-replica loops use RunIfLeader.
	WithLock(ctx context.Context, lockName string, fn func(context.Context) error) error

	// Lock is the non-closure form of WithLock: it acquires lockName (blocking until held or ctx is cancelled) and returns a release
	// func the caller MUST invoke (typically deferred) to free the lock. It exists for critical sections that cannot be expressed as
	// a single closure — notably the boot sequence, which assigns several bounded-context handles that must outlive the locked
	// region. Same short-critical-section constraint as WithLock (no keep-alive). Returns ctx's error if cancelled before acquire.
	Lock(ctx context.Context, lockName string) (release func(), err error)
}

// mysqlCoordinator is the MySQL-advisory-lock Coordinator.
type mysqlCoordinator struct {
	db                *sqlx.DB
	pollInterval      time.Duration
	keepAliveInterval time.Duration
	logger            *slog.Logger
}

// Option configures a mysqlCoordinator.
type Option func(*mysqlCoordinator)

// WithPollInterval overrides the non-leader re-attempt interval. Values <= 0 are ignored. Tests use a short interval to keep
// failover assertions fast.
func WithPollInterval(d time.Duration) Option {
	return func(c *mysqlCoordinator) {
		if d > 0 {
			c.pollInterval = d
		}
	}
}

// WithKeepAliveInterval overrides how often the leader pings its lock connection. Values <= 0 are ignored. Tests use a short
// interval so the relinquish-on-connection-loss path is exercised quickly.
func WithKeepAliveInterval(d time.Duration) Option {
	return func(c *mysqlCoordinator) {
		if d > 0 {
			c.keepAliveInterval = d
		}
	}
}

// NewMySQL builds a Coordinator backed by db's MySQL advisory locks. db must allow at least one spare pooled connection per
// concurrently-held lock, since each held lock pins a dedicated connection for its lifetime.
func NewMySQL(db *sqlx.DB, logger *slog.Logger, opts ...Option) *mysqlCoordinator {
	if logger == nil {
		logger = slog.Default()
	}
	c := &mysqlCoordinator{db: db, pollInterval: defaultPollInterval, keepAliveInterval: defaultKeepAliveInterval, logger: logger}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *mysqlCoordinator) RunIfLeader(ctx context.Context, lockName string, fn func(context.Context) error) error {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		conn, acquired, err := c.tryAcquire(ctx, lockName)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil // shutting down; a transient acquire error during shutdown is not worth surfacing
			}
			c.logger.WarnContext(ctx, "leader lock acquire failed; will retry", "lock", lockName, "err", err)
		case acquired:
			c.logger.InfoContext(ctx, "acquired leadership", "lock", lockName)
			runErr := c.runAsLeader(ctx, lockName, conn, fn)
			if ctx.Err() != nil {
				return runErr // parent cancelled: graceful shutdown, we are done
			}
			// We lost the lease without the parent cancelling (the keep-alive ping failed, i.e. the lock connection dropped).
			// Fall through to re-acquire so leadership is not abandoned after a transient connection loss.
			c.logger.WarnContext(ctx, "lost leadership; will attempt to re-acquire", "lock", lockName)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// runAsLeader runs fn while this replica holds the lock. fn runs under a lease context derived from ctx; a keep-alive goroutine
// pings the lock connection so MySQL's wait_timeout cannot silently close it, and if a ping fails (the connection dropped) it
// cancels the lease so fn — a long-running loop — stops promptly rather than acting as leader after the lock is gone. The lock is
// released on return (deferred, so a panic in fn still frees it); the keep-alive is stopped and joined before release so it never
// touches the connection concurrently with RELEASE_LOCK / Close.
func (c *mysqlCoordinator) runAsLeader(ctx context.Context, lockName string, conn *sql.Conn, fn func(context.Context) error) error {
	leaseCtx, cancelLease := context.WithCancel(ctx)
	keepAliveDone := make(chan struct{})
	go func() {
		defer close(keepAliveDone)
		c.keepAlive(leaseCtx, cancelLease, lockName, conn)
	}()
	defer func() {
		cancelLease()
		<-keepAliveDone // wait for the keep-alive to stop using conn before releasing it
		c.release(context.WithoutCancel(ctx), lockName, conn)
	}()
	return fn(leaseCtx)
}

// keepAlive pings the lock connection every keepAliveInterval so MySQL does not close it as idle while the leader callback runs. A
// failed ping means the connection (and thus the lock) is gone, so it relinquishes the lease and returns.
func (c *mysqlCoordinator) keepAlive(ctx context.Context, relinquish context.CancelFunc, lockName string, conn *sql.Conn) {
	ticker := time.NewTicker(c.keepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := conn.PingContext(ctx); err != nil {
				c.logger.WarnContext(ctx, "leader lock keep-alive failed; relinquishing leadership", "lock", lockName, "err", err)
				relinquish()
				return
			}
		}
	}
}

func (c *mysqlCoordinator) DoOnceIfLeader(ctx context.Context, lockName string, fn func(context.Context) error) (bool, error) {
	conn, acquired, err := c.tryAcquire(ctx, lockName)
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	defer c.release(context.WithoutCancel(ctx), lockName, conn)
	return true, fn(ctx)
}

func (c *mysqlCoordinator) WithLock(ctx context.Context, lockName string, fn func(context.Context) error) error {
	release, err := c.Lock(ctx, lockName)
	if err != nil {
		return err
	}
	defer release()
	return fn(ctx)
}

// Lock acquires lockName, blocking until it is held or ctx is cancelled, and returns a release func the caller MUST invoke to free
// it. release runs RELEASE_LOCK on a cancellation-stripped, timeout-bounded context (so a graceful shutdown still frees the lock)
// and returns the dedicated connection to the pool.
func (c *mysqlCoordinator) Lock(ctx context.Context, lockName string) (func(), error) {
	conn, err := c.acquireBlocking(ctx, lockName)
	if err != nil {
		return nil, err
	}
	return func() { c.release(context.WithoutCancel(ctx), lockName, conn) }, nil
}

// acquireBlocking grabs a dedicated connection and blocks on GET_LOCK until the lock is held or ctx is cancelled. The caller MUST
// release the returned connection (Lock does so). It loops because a single GET_LOCK attempt is bounded at lockAcquireWaitSeconds;
// between attempts it re-checks ctx so a cancelled boot does not hang.
func (c *mysqlCoordinator) acquireBlocking(ctx context.Context, lockName string) (*sql.Conn, error) {
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("open lock connection: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		var got sql.NullInt64
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", lockName, lockAcquireWaitSeconds).Scan(&got); err != nil {
			_ = conn.Close()
			// A ctx cancelled mid-wait surfaces here as a query error; honour the documented contract ("returns ctx's error if
			// cancelled before the lock is acquired") by returning the cancellation directly rather than a wrapped get_lock error.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, fmt.Errorf("get_lock %q (blocking): %w", lockName, err)
		}
		if !got.Valid {
			// NULL is an error per the MySQL docs (OOM, killed session, bad argument), not contention. Surface it.
			_ = conn.Close()
			return nil, fmt.Errorf("get_lock %q returned NULL", lockName)
		}
		if got.Int64 == 1 {
			return conn, nil
		}
		// got.Int64 == 0: the attempt timed out while another session held the lock. Loop to re-check ctx, then retry.
	}
}

// tryAcquire grabs a dedicated connection and makes one non-blocking GET_LOCK attempt on it. On success it returns the held
// connection, which the caller MUST release. On a lost race or error it returns the connection to the pool and reports the
// outcome.
func (c *mysqlCoordinator) tryAcquire(ctx context.Context, lockName string) (*sql.Conn, bool, error) {
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("open lock connection: %w", err)
	}
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", lockName, lockWaitSeconds).Scan(&got); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("get_lock %q: %w", lockName, err)
	}
	if !got.Valid {
		// NULL from GET_LOCK is an error (out of memory, the session was killed, or a bad argument) per the MySQL docs, not mere
		// contention. Surface it so RunIfLeader logs + retries and DoOnceIfLeader's caller can fail open, rather than silently
		// treating it as "another replica holds the lock".
		_ = conn.Close()
		return nil, false, fmt.Errorf("get_lock %q returned NULL", lockName)
	}
	if got.Int64 != 1 {
		// 0 = the lock is held by another session: we are simply not the leader. Return the connection to the pool.
		_ = conn.Close()
		return nil, false, nil
	}
	return conn, true, nil
}

// release frees the lock and returns the connection to the pool. The caller passes a cancellation-stripped context so RELEASE_LOCK
// runs even during a graceful shutdown; release re-imposes a releaseTimeout deadline so an unresponsive database cannot block the
// (often deferred) release indefinitely. RELEASE_LOCK is explicit because returning the connection to the pool does NOT end the
// session, so the session-scoped lock would otherwise linger until the pooled connection is eventually closed.
func (c *mysqlCoordinator) release(ctx context.Context, lockName string, conn *sql.Conn) {
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	if _, err := conn.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", lockName); err != nil {
		c.logger.WarnContext(ctx, "release leader lock failed", "lock", lockName, "err", err)
	}
	_ = conn.Close()
}
