package graph

import (
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

func TestProcessBatchForkExecExit(t *testing.T) {
	s := openTestStore(t)
	b := NewBuilder(s, slog.Default())

	events := []store.Event{
		{
			EventID: "fork-1", HostID: "host-1", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 100, "parent_pid": 1}`),
		},
		{
			EventID: "exec-1", HostID: "host-1", TimestampNs: 2000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 100, "ppid": 1, "path": "/usr/bin/ls", "args": ["ls", "-la"], "uid": 501, "gid": 20}`),
		},
		{
			EventID: "exit-1", HostID: "host-1", TimestampNs: 3000,
			EventType: "exit",
			Payload:   json.RawMessage(`{"pid": 100, "exit_code": 0}`),
		},
	}

	err := s.InsertEvents(events)
	require.NoError(t, err)
	err = b.ProcessBatch(events)
	require.NoError(t, err)

	proc, err := s.GetProcessByPID("host-1", 100, 2500)
	require.NoError(t, err)
	require.NotNil(t, proc, "expected to find process 100")

	assert.Equal(t, "/usr/bin/ls", proc.Path)
	assert.Equal(t, 1, proc.PPID)
	require.NotNil(t, proc.ExitTimeNs, "expected exit_time_ns to be set")
	assert.Equal(t, int64(3000), *proc.ExitTimeNs)
}

func TestProcessBatchExecWithoutFork(t *testing.T) {
	s := openTestStore(t)
	b := NewBuilder(s, slog.Default())

	events := []store.Event{
		{
			EventID: "exec-nofork-1", HostID: "host-2", TimestampNs: 5000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 200, "ppid": 1, "path": "/usr/bin/cat", "args": ["cat", "/etc/hosts"], "uid": 0, "gid": 0}`),
		},
	}

	err := s.InsertEvents(events)
	require.NoError(t, err)
	err = b.ProcessBatch(events)
	require.NoError(t, err)

	proc, err := s.GetProcessByPID("host-2", 200, 5000)
	require.NoError(t, err)
	require.NotNil(t, proc, "expected to find process 200 (exec-without-fork)")
	assert.Equal(t, "/usr/bin/cat", proc.Path)
}

func TestProcessBatchPIDReuse(t *testing.T) {
	s := openTestStore(t)
	b := NewBuilder(s, slog.Default())

	events := []store.Event{
		{
			EventID: "fork-reuse-1", HostID: "host-3", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 300, "parent_pid": 1}`),
		},
		{
			EventID: "exec-reuse-1", HostID: "host-3", TimestampNs: 2000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 300, "ppid": 1, "path": "/usr/bin/first", "args": [], "uid": 0, "gid": 0}`),
		},
		// PID 300 is reused without an exit — fork arrives for same PID.
		{
			EventID: "fork-reuse-2", HostID: "host-3", TimestampNs: 4000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 300, "parent_pid": 1}`),
		},
		{
			EventID: "exec-reuse-2", HostID: "host-3", TimestampNs: 5000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 300, "ppid": 1, "path": "/usr/bin/second", "args": [], "uid": 0, "gid": 0}`),
		},
	}

	err := s.InsertEvents(events)
	require.NoError(t, err)
	err = b.ProcessBatch(events)
	require.NoError(t, err)

	// The second instance should be active at timestamp 5000.
	proc, err := s.GetProcessByPID("host-3", 300, 5000)
	require.NoError(t, err)
	require.NotNil(t, proc, "expected to find process 300")
	assert.Equal(t, "/usr/bin/second", proc.Path)
}

func TestProcessBatchOutOfOrderEvents(t *testing.T) {
	s := openTestStore(t)
	b := NewBuilder(s, slog.Default())

	// Events arrive in reverse order (exit, exec, fork). ProcessBatch should
	// sort by TimestampNs internally and produce the correct result.
	events := []store.Event{
		{
			EventID: "ooo-exit", HostID: "host-ooo", TimestampNs: 3000,
			EventType: "exit",
			Payload:   json.RawMessage(`{"pid": 400, "exit_code": 0}`),
		},
		{
			EventID: "ooo-exec", HostID: "host-ooo", TimestampNs: 2000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 400, "ppid": 1, "path": "/usr/bin/whoami", "args": ["whoami"], "uid": 501, "gid": 20}`),
		},
		{
			EventID: "ooo-fork", HostID: "host-ooo", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 400, "parent_pid": 1}`),
		},
	}

	err := s.InsertEvents(events)
	require.NoError(t, err)
	err = b.ProcessBatch(events)
	require.NoError(t, err)

	proc, err := s.GetProcessByPID("host-ooo", 400, 2500)
	require.NoError(t, err)
	require.NotNil(t, proc)
	assert.Equal(t, "/usr/bin/whoami", proc.Path)
	require.NotNil(t, proc.ExitTimeNs)
	assert.Equal(t, int64(3000), *proc.ExitTimeNs)
}

func TestProcessBatchPartialFailure(t *testing.T) {
	s := openTestStore(t)
	b := NewBuilder(s, slog.Default())

	events := []store.Event{
		{
			EventID: "good-fork", HostID: "host-partial", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 500, "parent_pid": 1}`),
		},
		{
			// Valid JSON but wrong types — will fail unmarshalling into forkPayload.
			EventID: "bad-fork", HostID: "host-partial", TimestampNs: 2000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": "not_a_number", "parent_pid": "also_bad"}`),
		},
		{
			EventID: "good-exec", HostID: "host-partial", TimestampNs: 3000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 500, "ppid": 1, "path": "/usr/bin/echo", "args": ["echo"], "uid": 0, "gid": 0}`),
		},
	}

	err := s.InsertEvents(events)
	require.NoError(t, err)

	err = b.ProcessBatch(events)
	require.Error(t, err, "expected error from partial failure")
	assert.Contains(t, err.Error(), "1 event(s) failed")

	// The good events should still have been processed.
	proc, err := s.GetProcessByPID("host-partial", 500, 3000)
	require.NoError(t, err)
	require.NotNil(t, proc, "good events should still be processed despite partial failure")
	assert.Equal(t, "/usr/bin/echo", proc.Path)
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	s, err := store.New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	// Truncate tables to ensure no stale data from previous test runs.
	_, err = s.DB().Exec("TRUNCATE TABLE processes")
	require.NoError(t, err)
	_, err = s.DB().Exec("TRUNCATE TABLE events")
	require.NoError(t, err)
	return s
}
