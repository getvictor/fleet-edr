package commandledger_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/commandledger"
)

func openTestStore(t *testing.T) *commandledger.Store {
	t.Helper()
	s, err := commandledger.Open(t.Context(), filepath.Join(t.TempDir(), "commands.db"), commandledger.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStore(t *testing.T) {
	t.Parallel()

	t.Run("an unknown command id is not seen", func(t *testing.T) {
		t.Parallel()
		s := openTestStore(t)
		_, _, seen, err := s.Lookup(t.Context(), 42)
		require.NoError(t, err)
		assert.False(t, seen)
	})

	t.Run("mark then lookup round-trips status and result", func(t *testing.T) {
		t.Parallel()
		s := openTestStore(t)
		require.NoError(t, s.Mark(t.Context(), 7, "completed", json.RawMessage(`{"killed_pid":99}`)))
		status, result, seen, err := s.Lookup(t.Context(), 7)
		require.NoError(t, err)
		assert.True(t, seen)
		assert.Equal(t, "completed", status)
		assert.JSONEq(t, `{"killed_pid":99}`, string(result))
	})

	t.Run("mark upserts the status for an id", func(t *testing.T) {
		t.Parallel()
		s := openTestStore(t)
		require.NoError(t, s.Mark(t.Context(), 5, "executing", nil)) // write-ahead claim
		require.NoError(t, s.Mark(t.Context(), 5, "completed", json.RawMessage(`{"ok":true}`)))
		status, result, seen, err := s.Lookup(t.Context(), 5)
		require.NoError(t, err)
		require.True(t, seen)
		assert.Equal(t, "completed", status)
		assert.JSONEq(t, `{"ok":true}`, string(result))
	})

	t.Run("prune deletes only rows older than maxAge", func(t *testing.T) {
		t.Parallel()
		s := openTestStore(t)
		require.NoError(t, s.Mark(t.Context(), 1, "completed", nil))
		// A fresh row is retained at a 1h horizon.
		n, err := s.Prune(t.Context(), time.Hour)
		require.NoError(t, err)
		assert.Equal(t, int64(0), n)
		// A negative maxAge puts the cutoff in the future, so the row is now "old" and is deleted.
		n, err = s.Prune(t.Context(), -time.Hour)
		require.NoError(t, err)
		assert.Equal(t, int64(1), n)
		_, _, seen, err := s.Lookup(t.Context(), 1)
		require.NoError(t, err)
		assert.False(t, seen)
	})
}

// TestStore_SurvivesReopen pins the durability that makes the dedup restart-safe: a recorded outcome is still present after the store is
// closed and reopened (the agent-restart case).
//
// spec:agent-command-executor/command-execution-is-deduplicated-durably-across-transports-and-restarts/a-recorded-outcome-survives-an-agent-restart
func TestStore_SurvivesReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "commands.db")
	s1, err := commandledger.Open(t.Context(), path, commandledger.Options{})
	require.NoError(t, err)
	require.NoError(t, s1.Mark(t.Context(), 11, "completed", json.RawMessage(`{"killed_pid":1}`)))
	require.NoError(t, s1.Close())

	s2, err := commandledger.Open(t.Context(), path, commandledger.Options{}) // simulate an agent restart
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })
	status, result, seen, err := s2.Lookup(t.Context(), 11)
	require.NoError(t, err)
	assert.True(t, seen)
	assert.Equal(t, "completed", status)
	assert.JSONEq(t, `{"killed_pid":1}`, string(result))
}
