package commander

import (
	"encoding/json"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/commandledger"
)

// TestExecutor_DurableDedupAcrossRestart is the integration-fidelity #558 regression. The other executor dedup tests use the in-memory
// fakeLedger; this one drives Execute through the REAL durable commandledger.Store (SQLite) across a close/reopen, the automated
// counterpart of the manual dev-server + VM verification. It reproduces the full push-execute -> stream-drop -> agent-restart ->
// poll-refetch sequence against the actual persistence layer: the executor + the on-disk ledger together, not the executor against a
// stand-in. Each subtest opens the push-side store, acts, closes it (the agent stops before the server saw the outcome), then reopens
// the same file as the poll-side store (the restart) and delivers the same command id.
func TestExecutor_DurableDedupAcrossRestart(t *testing.T) {
	t.Parallel()

	// spec:agent-command-executor/command-execution-is-deduplicated-durably-across-transports-and-restarts/a-command-executed-on-one-transport-is-not-re-executed-by-the-other
	// spec:agent-command-executor/command-execution-is-deduplicated-durably-across-transports-and-restarts/a-recorded-outcome-survives-an-agent-restart
	t.Run("a completed outcome replays across a restart without re-running the side effect", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "commands.db")
		cmd := Command{ID: 558, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":4242}`)}
		var kills int

		pushLedger, err := commandledger.Open(t.Context(), path, commandledger.Options{})
		require.NoError(t, err)
		push := NewExecutor(nil, pushLedger, nil)
		push.kill = func(int, syscall.Signal) error { kills++; return nil }
		var pushReports []string
		push.Execute(t.Context(), cmd, recordReport(&pushReports))
		require.Equal(t, 1, kills, "the push path runs the kill once")
		require.Equal(t, []string{StatusAcked, StatusCompleted}, pushReports)
		require.NoError(t, pushLedger.Close()) // the agent stops before the server processed the outcome

		pollLedger, err := commandledger.Open(t.Context(), path, commandledger.Options{}) // the agent restarts, reopening the on-disk ledger
		require.NoError(t, err)
		t.Cleanup(func() { _ = pollLedger.Close() })
		poll := NewExecutor(nil, pollLedger, nil)
		poll.kill = func(int, syscall.Signal) error { kills++; return nil }
		var pollReports []string
		poll.Execute(t.Context(), cmd, recordReport(&pollReports))
		assert.Equal(t, 1, kills, "the poll path after a restart does not re-run the kill")
		assert.Equal(t, []string{StatusAcked, StatusCompleted}, pollReports, "it replays the recorded outcome; status stays completed")
	})

	// spec:agent-command-executor/command-execution-is-deduplicated-durably-across-transports-and-restarts/a-recorded-outcome-survives-an-agent-restart
	t.Run("a write-ahead claim left by a crash is terminalized, not re-run, across a restart", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "commands.db")
		cmd := Command{ID: 559, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":4243}`)}

		// A prior attempt claimed the command (write-ahead "executing") then the agent crashed before recording a terminal outcome.
		crashedLedger, err := commandledger.Open(t.Context(), path, commandledger.Options{})
		require.NoError(t, err)
		won, _, _, err := crashedLedger.Claim(t.Context(), cmd.ID, statusExecuting)
		require.NoError(t, err)
		require.True(t, won)
		require.NoError(t, crashedLedger.Close())

		pollLedger, err := commandledger.Open(t.Context(), path, commandledger.Options{}) // restart: the bare claim survives on disk
		require.NoError(t, err)
		t.Cleanup(func() { _ = pollLedger.Close() })
		var kills int
		poll := NewExecutor(nil, pollLedger, nil)
		poll.kill = func(int, syscall.Signal) error { kills++; return nil }
		var pollReports []string
		poll.Execute(t.Context(), cmd, recordReport(&pollReports))
		assert.Equal(t, 0, kills, "an interrupted prior attempt is never re-run after a restart, so a since-reused PID is never re-signalled")
		assert.Equal(t, []string{StatusAcked, StatusFailed}, pollReports, "the stranded claim is terminalized so re-delivery stops")
	})
}
