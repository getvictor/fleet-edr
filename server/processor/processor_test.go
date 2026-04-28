package processor

import (
	"context"
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
	proc := New(s, builder, nil, slog.Default(), time.Second, 500)

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

	// Verify events are unprocessed (read-only check, does not claim).
	count, err := s.CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	// Run one processing cycle.
	proc.ProcessOnce(ctx)

	// Events should now be marked as processed.
	count, err = s.CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "all events should be processed")

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
	proc := New(s, builder, nil, slog.Default(), time.Second, 500)

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

	count, err := s.CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestProcessOnceBatchLimit(t *testing.T) {
	s := store.OpenTestStore(t)
	builder := graph.NewBuilder(s, slog.Default())
	// Small batch size to test batching.
	proc := New(s, builder, nil, slog.Default(), time.Second, 2)

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
	count, err := s.CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "one event should remain after first batch")

	// Second cycle processes the remaining 1.
	proc.ProcessOnce(ctx)
	count, err = s.CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "all events should be processed after second batch")
}

// TestNewWithNilLoggerUsesDefault locks in the constructor's nil-logger
// fallback so callers (e.g. main wiring) can pass nil during tests or when no
// logger has been configured yet, and still get a valid Processor.
func TestNewWithNilLoggerUsesDefault(t *testing.T) {
	s := store.OpenTestStore(t)
	builder := graph.NewBuilder(s, slog.Default())
	proc := New(s, builder, nil, nil, time.Second, 500)
	require.NotNil(t, proc)
	require.NotNil(t, proc.logger)
}

// TestRunStopsOnContextCancel proves the ticker loop actually returns when its
// context is cancelled — without this we'd never cover the `<-ctx.Done()`
// branch that the agent main relies on for clean shutdown.
func TestRunStopsOnContextCancel(t *testing.T) {
	s := store.OpenTestStore(t)
	builder := graph.NewBuilder(s, slog.Default())
	proc := New(s, builder, nil, slog.Default(), 50*time.Millisecond, 500)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	done := make(chan error, 1)
	go func() { done <- proc.Run(ctx) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestRunDrainsViaTicker covers the `<-ticker.C` case in the Run loop. We use
// a very short interval and a context that lives just long enough for the
// ticker to fire at least once with an event already inserted.
func TestRunDrainsViaTicker(t *testing.T) {
	s := store.OpenTestStore(t)
	builder := graph.NewBuilder(s, slog.Default())
	proc := New(s, builder, nil, slog.Default(), 10*time.Millisecond, 500)

	require.NoError(t, s.InsertEvents(t.Context(), []store.Event{{
		EventID: "run-fork", HostID: "host-run", TimestampNs: 1000,
		EventType: "fork",
		Payload:   json.RawMessage(`{"child_pid": 300, "parent_pid": 1}`),
	}}))

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	require.NoError(t, proc.Run(ctx))

	count, err := s.CountUnprocessed(t.Context())
	require.NoError(t, err)
	assert.Zero(t, count, "ticker-driven Run should have processed the inserted event")
}
