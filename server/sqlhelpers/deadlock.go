package sqlhelpers

import (
	"context"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
)

// mysqlErrDeadlock is MySQL error 1213: "Deadlock found when trying to get lock; try restarting transaction". Under concurrent
// multi-replica writes, INSERT/UPDATE statements that touch overlapping secondary-index gaps can deadlock; MySQL rolls one back with
// 1213 and a retry of the same idempotent statement clears it.
const mysqlErrDeadlock = 1213

// IsDeadlockErr reports whether err wraps a MySQL deadlock (error 1213). Surface-level signal only: the caller decides whether the
// operation is safe to retry.
func IsDeadlockErr(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDeadlock
}

// WithDeadlockRetry runs fn up to maxAttempts times, retrying only on a MySQL deadlock (1213) with a linear backoff of attempt*step,
// honoring ctx cancellation between attempts. Any non-deadlock error returns immediately. fn MUST be idempotent: it is re-run verbatim
// on a deadlock. Shared by the data-plane stores whose concurrent writes can deadlock on gap locks (detection events, visibility
// event_queue).
func WithDeadlockRetry(ctx context.Context, maxAttempts int, step time.Duration, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !IsDeadlockErr(lastErr) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * step):
		}
	}
	return lastErr
}
