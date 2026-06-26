package eventlog

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/visibility/api"
)

func TestNew_NilDB(t *testing.T) {
	t.Parallel()
	_, err := New(nil)
	require.Error(t, err)
}

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
			assert.Equal(t, tc.want, isDeadlockErr(tc.err))
		})
	}
}

func TestWithDeadlockRetry(t *testing.T) {
	t.Parallel()
	deadlock := &mysql.MySQLError{Number: mysqlErrDeadlock}

	t.Run("succeeds first try", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := withDeadlockRetry(context.Background(), 5, time.Millisecond, func() error {
			calls++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("retries on deadlock then succeeds", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := withDeadlockRetry(context.Background(), 5, time.Millisecond, func() error {
			calls++
			if calls < 3 {
				return deadlock
			}
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 3, calls)
	})

	t.Run("returns non-deadlock error immediately", func(t *testing.T) {
		t.Parallel()
		other := errors.New("syntax error")
		calls := 0
		err := withDeadlockRetry(context.Background(), 5, time.Millisecond, func() error {
			calls++
			return other
		})
		require.ErrorIs(t, err, other)
		assert.Equal(t, 1, calls)
	})

	t.Run("gives up after maxAttempts on persistent deadlock", func(t *testing.T) {
		t.Parallel()
		calls := 0
		err := withDeadlockRetry(context.Background(), 3, time.Millisecond, func() error {
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
		err := withDeadlockRetry(ctx, 5, time.Second, func() error {
			return deadlock
		})
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestAppendArgs(t *testing.T) {
	t.Parallel()
	events := []api.Event{
		{EventID: "e1", HostID: "h1", TimestampNs: 10, IngestedAtNs: 11, EventType: "exec", Payload: json.RawMessage(`{"pid":1}`)},
		{EventID: "e2", HostID: "h1", TimestampNs: 20, IngestedAtNs: 21, EventType: "fork", Payload: json.RawMessage(`{"pid":2}`)},
	}
	placeholders, args, err := appendArgs(events)
	require.NoError(t, err)
	assert.Equal(t, []string{"(?, ?, ?, ?, ?, ?)", "(?, ?, ?, ?, ?, ?)"}, placeholders)
	require.Len(t, args, 12)
	// First row's flattened args, in column order.
	assert.Equal(t, "e1", args[0])
	assert.Equal(t, "h1", args[1])
	assert.Equal(t, int64(10), args[2])
	assert.Equal(t, int64(11), args[3])
	assert.Equal(t, "exec", args[4])
	assert.Equal(t, []byte(`{"pid":1}`), args[5])
}
