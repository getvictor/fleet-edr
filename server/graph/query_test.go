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

func TestBuildTree(t *testing.T) {
	s := openTreeTestStore(t)
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

	err := s.InsertEvents(events)
	require.NoError(t, err)
	err = b.ProcessBatch(events)
	require.NoError(t, err)

	tr := store.TimeRange{FromNs: 0, ToNs: 10000}
	roots, err := q.BuildTree("tree-host", tr, 500)
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
	s := openTreeTestStore(t)
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

	err := s.InsertEvents(events)
	require.NoError(t, err)
	err = b.ProcessBatch(events)
	require.NoError(t, err)

	detail, err := q.GetDetail("detail-host", 50, 2500)
	require.NoError(t, err)
	require.NotNil(t, detail, "expected to find process detail")

	assert.Equal(t, "/usr/bin/curl", detail.Process.Path)
	assert.Len(t, detail.NetworkConnections, 1)
	assert.Len(t, detail.DNSQueries, 1)
}

func openTreeTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	s, err := store.New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}
