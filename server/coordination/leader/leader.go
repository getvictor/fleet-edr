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

// lockWaitSeconds is the GET_LOCK timeout. 0 means non-blocking: GET_LOCK returns immediately (1 if free, 0 if held by another
// session). The scheduler retries every poll interval, so blocking inside GET_LOCK would only duplicate that wait.
const lockWaitSeconds = 0

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
}

// mysqlCoordinator is the MySQL-advisory-lock Coordinator.
type mysqlCoordinator struct {
	db           *sqlx.DB
	pollInterval time.Duration
	logger       *slog.Logger
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

// NewMySQL builds a Coordinator backed by db's MySQL advisory locks. db must allow at least one spare pooled connection per
// concurrently-held lock, since each held lock pins a dedicated connection for its lifetime.
func NewMySQL(db *sqlx.DB, logger *slog.Logger, opts ...Option) *mysqlCoordinator {
	if logger == nil {
		logger = slog.Default()
	}
	c := &mysqlCoordinator{db: db, pollInterval: defaultPollInterval, logger: logger}
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
			runErr := fn(ctx)
			// Release with cancellation stripped but values kept: fn returns because ctx was cancelled (graceful shutdown), yet
			// the lock must still be released promptly so a peer can take over.
			c.release(context.WithoutCancel(ctx), lockName, conn)
			return runErr
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
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
	if !got.Valid || got.Int64 != 1 {
		// 0 = held by another session, NULL = error/timeout. Either way we are not the leader; return the connection to the pool.
		_ = conn.Close()
		return nil, false, nil
	}
	return conn, true, nil
}

// release frees the lock and returns the connection to the pool. The caller passes a cancellation-stripped context so RELEASE_LOCK
// runs even during a graceful shutdown. RELEASE_LOCK is explicit because returning the connection to the pool does NOT end the
// session, so the session-scoped lock would otherwise linger until the pooled connection is eventually closed.
func (c *mysqlCoordinator) release(ctx context.Context, lockName string, conn *sql.Conn) {
	if _, err := conn.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", lockName); err != nil {
		c.logger.WarnContext(ctx, "release leader lock failed", "lock", lockName, "err", err)
	}
	_ = conn.Close()
}
