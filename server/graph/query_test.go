package graph

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

func TestBuildTree(t *testing.T) {
	s := store.OpenTestStore(t)
	b := NewBuilder(s, slog.Default())
	q := NewQuery(s)

	// Create a process hierarchy: init(1) -> bash(10) -> curl(11)
	events := []store.Event{
		{
			EventID: "tree-fork-1", HostID: "tree-host", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 10, "parent_pid": 1}`),
		},
		{
			EventID: "tree-exec-1", HostID: "tree-host", TimestampNs: 2000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 10, "ppid": 1, "path": "/bin/bash", "args": ["bash"], "uid": 501, "gid": 20}`),
		},
		{
			EventID: "tree-fork-2", HostID: "tree-host", TimestampNs: 3000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 11, "parent_pid": 10}`),
		},
		{
			EventID: "tree-exec-2", HostID: "tree-host", TimestampNs: 4000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 11, "ppid": 10, "path": "/usr/bin/curl", "args": ["curl", "https://example.com"], "uid": 501, "gid": 20}`),
		},
	}

	ctx := t.Context()
	err := s.InsertEvents(ctx, events)
	require.NoError(t, err)
	err = b.ProcessBatch(ctx, events)
	require.NoError(t, err)

	tr := store.TimeRange{FromNs: 0, ToNs: 10000}
	roots, err := q.BuildTree(ctx, "tree-host", tr, 500)
	require.NoError(t, err)
	require.Len(t, roots, 1)

	root := roots[0]
	assert.Equal(t, 10, root.PID)
	assert.Equal(t, "/bin/bash", root.Path)
	require.Len(t, root.Children, 1)

	child := root.Children[0]
	assert.Equal(t, 11, child.PID)
	assert.Equal(t, "/usr/bin/curl", child.Path)
}

func TestGetDetailWithNetworkEvents(t *testing.T) {
	s := store.OpenTestStore(t)
	b := NewBuilder(s, slog.Default())
	q := NewQuery(s)

	events := []store.Event{
		{
			EventID: "detail-fork", HostID: "detail-host", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 50, "parent_pid": 1}`),
		},
		{
			EventID: "detail-exec", HostID: "detail-host", TimestampNs: 2000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 50, "ppid": 1, "path": "/usr/bin/curl", "args": ["curl", "https://example.com"], "uid": 501, "gid": 20}`),
		},
		{
			EventID: "detail-net", HostID: "detail-host", TimestampNs: 2500,
			EventType: "network_connect",
			Payload: json.RawMessage(`{"pid": 50, "path": "/usr/bin/curl", "uid": 501, "protocol": "tcp",
				"direction": "outbound", "remote_address": "93.184.216.34", "remote_port": 443, "remote_hostname": "example.com"}`),
		},
		{
			EventID: "detail-dns", HostID: "detail-host", TimestampNs: 2200,
			EventType: "dns_query",
			Payload:   json.RawMessage(`{"pid": 50, "path": "/usr/bin/curl", "uid": 501, "query_name": "example.com", "query_type": "A", "response_addresses": ["93.184.216.34"]}`),
		},
		{
			EventID: "detail-exit", HostID: "detail-host", TimestampNs: 3000,
			EventType: "exit",
			Payload:   json.RawMessage(`{"pid": 50, "exit_code": 0}`),
		},
	}

	ctx := t.Context()
	err := s.InsertEvents(ctx, events)
	require.NoError(t, err)
	err = b.ProcessBatch(ctx, events)
	require.NoError(t, err)

	detail, err := q.GetDetail(ctx, "detail-host", 50, 2500)
	require.NoError(t, err)
	require.NotNil(t, detail, "expected to find process detail")

	assert.Equal(t, "/usr/bin/curl", detail.Process.Path)
	assert.Len(t, detail.NetworkConnections, 1)
	assert.Len(t, detail.DNSQueries, 1)
}

func TestBuildForestGrandchildren(t *testing.T) {
	// Pure unit test — no MySQL needed. Verifies 3-level tree is preserved.
	procs := []store.Process{
		{ID: 1, PID: 10, PPID: 0, Path: "/sbin/init", ForkTimeNs: 1000},
		{ID: 2, PID: 20, PPID: 10, Path: "/bin/bash", ForkTimeNs: 2000},
		{ID: 3, PID: 30, PPID: 20, Path: "/usr/bin/curl", ForkTimeNs: 3000},
	}

	roots := buildForest(procs)
	require.Len(t, roots, 1, "expected 1 root")
	assert.Equal(t, 10, roots[0].PID)

	require.Len(t, roots[0].Children, 1, "expected 1 child of root")
	child := roots[0].Children[0]
	assert.Equal(t, 20, child.PID)

	require.Len(t, child.Children, 1, "expected 1 grandchild")
	grandchild := child.Children[0]
	assert.Equal(t, 30, grandchild.PID)
	assert.Equal(t, "/usr/bin/curl", grandchild.Path)
}

func TestBuildForestPIDReuse(t *testing.T) {
	// Two processes with same PID but different DB IDs should be separate nodes.
	procs := []store.Process{
		{ID: 1, PID: 100, PPID: 0, Path: "/usr/bin/first", ForkTimeNs: 1000},
		{ID: 2, PID: 100, PPID: 0, Path: "/usr/bin/second", ForkTimeNs: 5000},
	}

	roots := buildForest(procs)
	require.Len(t, roots, 2, "expected 2 separate roots for reused PID")

	paths := map[string]bool{roots[0].Path: true, roots[1].Path: true}
	assert.True(t, paths["/usr/bin/first"], "expected /usr/bin/first in roots")
	assert.True(t, paths["/usr/bin/second"], "expected /usr/bin/second in roots")
}

func TestGetDetailRunningProcess(t *testing.T) {
	s := store.OpenTestStore(t)
	b := NewBuilder(s, slog.Default())
	q := NewQuery(s)

	// Create a process that has NOT exited — no exit event.
	events := []store.Event{
		{
			EventID: "running-fork", HostID: "running-host", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 60, "parent_pid": 1}`),
		},
		{
			EventID: "running-exec", HostID: "running-host", TimestampNs: 2000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 60, "ppid": 1, "path": "/usr/sbin/sshd", "args": ["sshd"], "uid": 0, "gid": 0}`),
		},
		{
			EventID: "running-net", HostID: "running-host", TimestampNs: 3000,
			EventType: "network_connect",
			Payload:   json.RawMessage(`{"pid": 60, "path": "/usr/sbin/sshd", "uid": 0, "protocol": "tcp", "direction": "inbound", "remote_address": "10.0.0.1", "remote_port": 22}`),
		},
	}

	ctx := t.Context()
	err := s.InsertEvents(ctx, events)
	require.NoError(t, err)
	err = b.ProcessBatch(ctx, events)
	require.NoError(t, err)

	// Process has no exit — GetDetail should still work using the 30-day bound.
	detail, err := q.GetDetail(ctx, "running-host", 60, 2500)
	require.NoError(t, err)
	require.NotNil(t, detail, "expected to find running process detail")

	assert.Equal(t, "/usr/sbin/sshd", detail.Process.Path)
	assert.Nil(t, detail.Process.ExitTimeNs, "process should still be running")
	assert.Len(t, detail.NetworkConnections, 1, "expected 1 network connection")
}

// TestGetDetailCrossSourceClockSkew reproduces the scenario from issue #7:
// an NE-emitted network_connect event arrives with a source-kernel
// timestamp_ns BEFORE the ES-emitted fork event of the same process
// (typical ~50-100ms inversion observed on real hardware). Pre-fix this
// made ProcessDetail drop the event entirely. Post-fix the server stamps
// ingest times independently and correlates on those, so the event
// surfaces even though its kernel timestamp is inverted.
func TestGetDetailCrossSourceClockSkew(t *testing.T) {
	s := store.OpenTestStore(t)
	b := NewBuilder(s, slog.Default())
	q := NewQuery(s)
	ctx := t.Context()

	const hostID = "skew-host"

	// Batch 1: NE-emitted network_connect arrives first at the server, with
	// a kernel timestamp 100ms *before* the still-unseen fork.
	netEvents := []store.Event{
		{
			EventID: "skew-net", HostID: hostID,
			TimestampNs: 999_900_000_000, // fork_time - 100ms
			EventType:   "network_connect",
			Payload: json.RawMessage(
				`{"pid": 70, "path": "/usr/bin/nc", "uid": 501, "protocol": "tcp", ` +
					`"direction": "outbound", "remote_address": "1.1.1.1", "remote_port": 443}`),
		},
	}
	require.NoError(t, s.InsertEventsAt(ctx, netEvents, 1_000_000_000))

	// Batch 2: ES-emitted fork+exec+exit arrive in a later upload. Their
	// kernel times are all *after* the network_connect's kernel time, but
	// their server ingest time is higher than the network_connect's too —
	// that's the key property we correlate on.
	procEvents := []store.Event{
		{
			EventID: "skew-fork", HostID: hostID, TimestampNs: 1_000_000_000_000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 70, "parent_pid": 1}`),
		},
		{
			EventID: "skew-exec", HostID: hostID, TimestampNs: 1_000_000_100_000,
			EventType: "exec",
			Payload: json.RawMessage(
				`{"pid": 70, "ppid": 1, "path": "/usr/bin/nc", "args": ["nc","1.1.1.1","443"], "uid": 501, "gid": 20}`),
		},
		{
			EventID: "skew-exit", HostID: hostID, TimestampNs: 1_000_001_000_000,
			EventType: "exit",
			Payload:   json.RawMessage(`{"pid": 70, "exit_code": 0}`),
		},
	}
	require.NoError(t, s.InsertEventsAt(ctx, procEvents, 2_000_000_000))

	// Processor materializes the process row from the fork batch.
	require.NoError(t, b.ProcessBatch(ctx, procEvents))

	// GetDetail must surface the network_connect despite its kernel time
	// being earlier than the fork kernel time, because correlation runs on
	// server-stamped ingest times.
	detail, err := q.GetDetail(ctx, hostID, 70, 1_000_000_100_000)
	require.NoError(t, err)
	require.NotNil(t, detail)
	assert.Equal(t, "/usr/bin/nc", detail.Process.Path)
	assert.Len(t, detail.NetworkConnections, 1,
		"network_connect with inverted kernel timestamp must still surface via ingest-time correlation")
}
