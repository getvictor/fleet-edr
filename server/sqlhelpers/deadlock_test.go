package sqlhelpers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsDeadlockErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"deadlock", &mysql.MySQLError{Number: mysqlErrDeadlock}, true},
		{"other mysql error", &mysql.MySQLError{Number: 1062}, false},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, IsDeadlockErr(tc.err))
		})
	}
}

func TestWithDeadlockRetry(t *testing.T) {
	t.Parallel()
	deadlock := &mysql.MySQLError{Number: mysqlErrDeadlock}

	t.Run("succeeds first try", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := WithDeadlockRetry(context.Background(), 5, time.Millisecond, func() error {
			calls++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("retries on deadlock then succeeds", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := WithDeadlockRetry(context.Background(), 5, time.Millisecond, func() error {
			calls++
			if calls < 3 {
				return deadlock
			}
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 3, calls)
	})

	// The case that keeps the predicate honest (issue #868). Lock wait timeout is deadlock's obvious sibling and is the error most
	// likely to be added here by someone making this "more robust", and it is the one that must not be: with
	// innodb_rollback_on_timeout OFF, the default, 1205 rolls back only the timed-out STATEMENT and leaves the rest of its
	// transaction intact, so a callback spanning a transaction would be re-run on top of what its earlier statements had already
	// done. A generic error does not cover this, because nobody would widen the predicate to include a syntax error.
	t.Run("does not retry a lock wait timeout, which rolls back only the statement", func(t *testing.T) {
		t.Parallel()
		lockWait := &mysql.MySQLError{Number: 1205}
		calls := 0
		err := WithDeadlockRetry(context.Background(), 5, time.Millisecond, func() error {
			calls++
			return lockWait
		})
		require.ErrorIs(t, err, lockWait)
		assert.Equal(t, 1, calls, "the helper cannot know whether its callback spans a transaction, so it does not retry this")
	})

	t.Run("returns non-deadlock error immediately", func(t *testing.T) {
		t.Parallel()
		other := errors.New("syntax error")
		calls := 0
		err := WithDeadlockRetry(context.Background(), 5, time.Millisecond, func() error {
			calls++
			return other
		})
		require.ErrorIs(t, err, other)
		assert.Equal(t, 1, calls)
	})

	t.Run("gives up after maxAttempts on persistent deadlock", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := WithDeadlockRetry(context.Background(), 3, time.Millisecond, func() error {
			calls++
			return deadlock
		})
		require.Error(t, err)
		assert.Equal(t, 3, calls)
	})

	t.Run("honors context cancellation between retries", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := WithDeadlockRetry(ctx, 5, time.Second, func() error {
			return deadlock
		})
		require.ErrorIs(t, err, context.Canceled)
	})
}
