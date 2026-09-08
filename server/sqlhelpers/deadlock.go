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
// honoring ctx cancellation between attempts. Any non-deadlock error returns immediately. Shared by the data-plane stores whose
// concurrent writes can deadlock on gap locks (detection events, visibility event_queue).
//
// fn must be safe to RE-RUN AFTER A ROLLBACK. That is weaker than idempotent, and the difference matters because most callers here
// are not idempotent: the statistics and match-count writes are additive upserts, and running one twice against a row that kept the
// first attempt's effect would double it (issue #868). They are safe anyway, because 1213 is the one error that guarantees the
// attempt left nothing behind: InnoDB rolls the victim transaction back entirely before returning it, so the retry adds once.
//
// This is why the predicate is 1213 ALONE and must stay that way. Lock wait timeout (1205) is its obvious sibling and is NOT the
// same thing: it rolls back the statement, not necessarily the transaction, so retrying an additive write on it could add twice.
// Widening this predicate to "looks like contention" would break every additive caller silently, which is a change to their
// correctness rather than to this helper's robustness.
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
