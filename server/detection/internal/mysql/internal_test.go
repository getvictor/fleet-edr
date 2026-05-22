package mysql

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isDeadlockErr is the gatekeeper for the insert-retry loop; if it misclassifies, the retry either fires on the wrong error class
// (potentially looping on a non-transient failure) or never fires when the deadlock shows up wrapped (the production path wraps
// with fmt.Errorf("insert %s: %w", ...)).
func TestIsDeadlockErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not a deadlock", nil, false},
		{"plain error is not a deadlock", errors.New("connection refused"), false},
		{"different mysql error (1062 dup key)", &mysql.MySQLError{Number: 1062, Message: "duplicate"}, false},
		{"bare deadlock error", &mysql.MySQLError{Number: 1213, Message: "Deadlock found"}, true},
		{"wrapped deadlock error", fmt.Errorf("insert evt-1: %w",
			&mysql.MySQLError{Number: 1213, Message: "Deadlock found"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isDeadlockErr(tc.err))
		})
	}
}

// TestWithDeadlockRetry pins the retry-loop contract: succeed-first-attempt, return-non-deadlock-immediately, retry-on-deadlock-then-
// succeed, exhaust-attempts-and-return-last-deadlock, honor-context-cancel-during-backoff. The wall-clock cost of each subtest is
// bounded by step (1ms here) times the number of retries, so the whole test stays well under 100ms.
func TestWithDeadlockRetry(t *testing.T) {
	deadlockErr := &mysql.MySQLError{Number: 1213, Message: "Deadlock found"}
	const step = 1 * time.Millisecond

	t.Run("success on first attempt", func(t *testing.T) {
		calls := 0
		err := withDeadlockRetry(t.Context(), 5, step, func() error {
			calls++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls, "fn must be invoked exactly once on a clean success")
	})

	t.Run("non-deadlock error returns immediately without retry", func(t *testing.T) {
		boom := errors.New("boom")
		calls := 0
		err := withDeadlockRetry(t.Context(), 5, step, func() error {
			calls++
			return boom
		})
		require.ErrorIs(t, err, boom)
		assert.Equal(t, 1, calls, "non-deadlock errors must short-circuit the loop")
	})

	t.Run("retries on deadlock then succeeds", func(t *testing.T) {
		calls := 0
		err := withDeadlockRetry(t.Context(), 5, step, func() error {
			calls++
			if calls < 3 {
				return fmt.Errorf("insert evt-1: %w", deadlockErr)
			}
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 3, calls, "fn must be retried until it stops returning deadlock")
	})

	t.Run("exhausts attempts and returns last deadlock error", func(t *testing.T) {
		calls := 0
		err := withDeadlockRetry(t.Context(), 3, step, func() error {
			calls++
			return deadlockErr
		})
		require.ErrorIs(t, err, deadlockErr)
		assert.Equal(t, 3, calls, "fn must be invoked maxAttempts times when every attempt deadlocks")
	})

	t.Run("context cancel during backoff returns ctx.Err", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		err := withDeadlockRetry(ctx, 5, 50*time.Millisecond, func() error {
			calls++
			if calls == 1 {
				// Cancel after the first deadlock so the backoff select picks up ctx.Done() before the timer fires.
				cancel()
			}
			return deadlockErr
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, calls, "context cancel during backoff must stop the loop before the next fn invocation")
	})
}

// White-box tests for package-private helpers. The other test file (store_test.go, package mysql_test) covers the public Store API
// against a real MySQL via testdb.
func TestDeduplicateStrings(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, []string{}},
		{"single element passthrough", []string{"a"}, []string{"a"}},
		{"all unique", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"all duplicates", []string{"x", "x", "x"}, []string{"x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := deduplicateStrings(tc.in)
			if tc.want == nil {
				assert.Nil(t, out)
				return
			}
			assert.Equal(t, tc.want, out)
		})
	}
}
