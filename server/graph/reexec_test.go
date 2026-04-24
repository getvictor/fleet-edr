package graph

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

// TestHandleExec_SamePIDReExecChain reproduces the scenario from issue #10:
// a shell's exec-optimization chain — `python → sh → bash → /tmp/payload` —
// arrives as a fork on PID 30683 followed by FOUR execve events on the same
// PID with no intervening fork. Pre-fix the processor upserted on PID so
// only the final /tmp/payload path survived. Post-fix we expect four rows
// linked via previous_exec_id.
func TestHandleExec_SamePIDReExecChain(t *testing.T) {
	s := store.OpenTestStore(t)
	b := NewBuilder(s, slog.Default())
	q := NewQuery(s)
	ctx := t.Context()

	const host = "reexec-host"
	const pid = 30683

	events := []store.Event{
		{EventID: "rx-fork", HostID: host, TimestampNs: 1_000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 30683, "parent_pid": 1}`)},
		{EventID: "rx-exec-py", HostID: host, TimestampNs: 2_000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 30683, "ppid": 1, "path": "/usr/bin/python3", "args": ["python3"], "uid": 501, "gid": 20}`)},
		{EventID: "rx-exec-sh", HostID: host, TimestampNs: 3_000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 30683, "ppid": 1, "path": "/bin/sh", "args": ["sh", "-c", "/tmp/payload"], "uid": 501, "gid": 20}`)},
		{EventID: "rx-exec-bash", HostID: host, TimestampNs: 4_000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 30683, "ppid": 1, "path": "/bin/bash", "args": ["bash", "-c", "/tmp/payload"], "uid": 501, "gid": 20}`)},
		{EventID: "rx-exec-pld", HostID: host, TimestampNs: 5_000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 30683, "ppid": 1, "path": "/tmp/payload", "args": ["/tmp/payload"], "uid": 501, "gid": 20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	require.NoError(t, b.ProcessBatch(ctx, events))

	// GetProcessByPID at a point after the final exec should return
	// /tmp/payload — the current generation.
	current, err := s.GetProcessByPID(ctx, host, pid, 6_000)
	require.NoError(t, err)
	require.NotNil(t, current)
	assert.Equal(t, "/tmp/payload", current.Path)
	require.NotNil(t, current.PreviousExecID, "current generation should link back to prior exec")

	// Fetch the whole chain. Oldest-first: python, sh, bash.
	detail, err := q.GetDetail(ctx, host, pid, 6_000)
	require.NoError(t, err)
	require.NotNil(t, detail)
	require.Len(t, detail.ReExecChain, 3, "expected three prior generations")
	assert.Equal(t, "/usr/bin/python3", detail.ReExecChain[0].Path)
	assert.Equal(t, "/bin/sh", detail.ReExecChain[1].Path)
	assert.Equal(t, "/bin/bash", detail.ReExecChain[2].Path)

	// Prior generations must be closed with exit_reason=reexec so analysts
	// can distinguish them from observed exits and TTL-reconciled greens.
	for _, prior := range detail.ReExecChain {
		require.NotNil(t, prior.ExitReason, "prior generation must be closed")
		assert.Equal(t, store.ExitReasonReExec, *prior.ExitReason)
		require.NotNil(t, prior.ExitTimeNs)
	}

	// fork_time_ns is preserved across the chain — every generation shares
	// the original fork identity.
	assert.Equal(t, detail.ReExecChain[0].ForkTimeNs, current.ForkTimeNs)
}

func TestHandleExec_SingleExecNoChain(t *testing.T) {
	s := store.OpenTestStore(t)
	b := NewBuilder(s, slog.Default())
	q := NewQuery(s)
	ctx := t.Context()

	events := []store.Event{
		{EventID: "se-fork", HostID: "one-host", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid": 42, "parent_pid": 1}`)},
		{EventID: "se-exec", HostID: "one-host", TimestampNs: 2000, EventType: "exec",
			Payload: json.RawMessage(`{"pid": 42, "ppid": 1, "path": "/bin/echo", "args": ["echo"], "uid": 501, "gid": 20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	require.NoError(t, b.ProcessBatch(ctx, events))

	detail, err := q.GetDetail(ctx, "one-host", 42, 2500)
	require.NoError(t, err)
	require.NotNil(t, detail)
	assert.Equal(t, "/bin/echo", detail.Process.Path)
	assert.Empty(t, detail.ReExecChain,
		"a plain fork+exec must not produce a re-exec chain")
	assert.Nil(t, detail.Process.PreviousExecID,
		"a root generation has no previous_exec_id")
}
