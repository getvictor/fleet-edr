package processor

import (
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

func TestProcessOncePicksUpUnprocessedEvents(t *testing.T) {
	s := store.OpenTestStore(t)
	builder := graph.NewBuilder(s, slog.Default())
	proc := New(s, builder, slog.Default(), time.Second, 500)

	ctx := t.Context()

	// Insert events directly — they start with processed = 0.
	events := []store.Event{
		{
			EventID: "proc-fork", HostID: "host-proc", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 100, "parent_pid": 1}`),
		},
		{
			EventID: "proc-exec", HostID: "host-proc", TimestampNs: 2000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 100, "ppid": 1, "path": "/usr/bin/ls", "args": ["ls"], "uid": 501, "gid": 20}`),
		},
		{
			EventID: "proc-exit", HostID: "host-proc", TimestampNs: 3000,
			EventType: "exit",
			Payload:   json.RawMessage(`{"pid": 100, "exit_code": 0}`),
		},
	}

	err := s.InsertEvents(ctx, events)
	require.NoError(t, err)

	// Verify events are unprocessed.
	unprocessed, err := s.FetchUnprocessed(ctx, 100)
	require.NoError(t, err)
	assert.Len(t, unprocessed, 3)

	// Run one processing cycle.
	proc.ProcessOnce(ctx)

	// Events should now be marked as processed.
	unprocessed, err = s.FetchUnprocessed(ctx, 100)
	require.NoError(t, err)
	assert.Empty(t, unprocessed, "all events should be processed")

	// Process tree should be built.
	process, err := s.GetProcessByPID(ctx, "host-proc", 100, 2500)
	require.NoError(t, err)
	require.NotNil(t, process)
	assert.Equal(t, "/usr/bin/ls", process.Path)
	require.NotNil(t, process.ExitTimeNs)
	assert.Equal(t, int64(3000), *process.ExitTimeNs)
}

func TestProcessOnceIsIdempotent(t *testing.T) {
	s := store.OpenTestStore(t)
	builder := graph.NewBuilder(s, slog.Default())
	proc := New(s, builder, slog.Default(), time.Second, 500)

	ctx := t.Context()

	events := []store.Event{
		{
			EventID: "idem-fork", HostID: "host-idem", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 200, "parent_pid": 1}`),
		},
	}
	err := s.InsertEvents(ctx, events)
	require.NoError(t, err)

	// Run twice — second run should be a no-op.
	proc.ProcessOnce(ctx)
	proc.ProcessOnce(ctx)

	unprocessed, err := s.FetchUnprocessed(ctx, 100)
	require.NoError(t, err)
	assert.Empty(t, unprocessed)
}

func TestProcessOnceBatchLimit(t *testing.T) {
	s := store.OpenTestStore(t)
	builder := graph.NewBuilder(s, slog.Default())
	// Small batch size to test batching.
	proc := New(s, builder, slog.Default(), time.Second, 2)

	ctx := t.Context()

	events := []store.Event{
		{EventID: "batch-a", HostID: "host-batch", TimestampNs: 1000, EventType: "exec",
			Payload: json.RawMessage(`{"pid": 10, "ppid": 1, "path": "/bin/a", "args": [], "uid": 0, "gid": 0}`)},
		{EventID: "batch-b", HostID: "host-batch", TimestampNs: 2000, EventType: "exec",
			Payload: json.RawMessage(`{"pid": 11, "ppid": 1, "path": "/bin/b", "args": [], "uid": 0, "gid": 0}`)},
		{EventID: "batch-c", HostID: "host-batch", TimestampNs: 3000, EventType: "exec",
			Payload: json.RawMessage(`{"pid": 12, "ppid": 1, "path": "/bin/c", "args": [], "uid": 0, "gid": 0}`)},
	}
	err := s.InsertEvents(ctx, events)
	require.NoError(t, err)

	// First cycle processes only 2.
	proc.ProcessOnce(ctx)
	unprocessed, err := s.FetchUnprocessed(ctx, 100)
	require.NoError(t, err)
	assert.Len(t, unprocessed, 1, "one event should remain after first batch")

	// Second cycle processes the remaining 1.
	proc.ProcessOnce(ctx)
	unprocessed, err = s.FetchUnprocessed(ctx, 100)
	require.NoError(t, err)
	assert.Empty(t, unprocessed, "all events should be processed after second batch")
}
