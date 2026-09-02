package catalog

import (
	"encoding/json"
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

// spec:server-detection-rules-engine/one-exec-chain-walk-for-both-shell-chain-rules/the-newest-suitable-generation-on-the-chain-is-preferred
//
// TestSuspiciousExecPrefersTheNewestShellWhenTheOldestIsOutTheWindow is the first of the two behaviour changes in issue #829.
//
// The temp arm used to walk the exec chain oldest-first, take the first suitable shell it found, and give up if that one failed
// the window. For `zsh -c 'bash -c "/tmp/payload"'`, where both shells exec in place at one PID, the oldest generation is exactly
// the one most likely to be stale, so a chain whose newer shell was well inside the window reported nothing. The shared walk the
// connect arm already used takes the newest suitable generation, and this arm now uses it.
func TestSuspiciousExecPrefersTheNewestShellWhenTheOldestIsOutTheWindow(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	const sec = int64(1_000_000_000)
	base := 100 * sec
	events := []api.Event{
		{EventID: "nw-fork-py", HostID: "host-a", TimestampNs: base, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "nw-exec-py", HostID: "host-a", TimestampNs: base + sec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "nw-fork-shell", HostID: "host-a", TimestampNs: base + 2*sec, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		// The OLDEST generation on the chain, 90 seconds before the trigger and so far outside the 30-second window.
		{EventID: "nw-exec-zsh", HostID: "host-a", TimestampNs: base + 3*sec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/zsh","args":["zsh","-c","bash -c /tmp/payload"],"uid":501,"gid":20}`)},
		// The NEWEST generation, five seconds before the trigger and comfortably inside it.
		{EventID: "nw-exec-bash", HostID: "host-a", TimestampNs: base + 88*sec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/bash","args":["bash","-c","/tmp/payload"],"uid":501,"gid":20}`)},
		{EventID: "nw-exec-payload", HostID: "host-a", TimestampNs: base + 93*sec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "the newest shell on the chain is inside the window, so the chain must be reported")
	assert.Contains(t, findings[0].Description, "/bin/bash",
		"the finding names the generation that actually ran the payload, not the stalest one on the chain")
}

// spec:server-detection-rules-engine/one-exec-chain-walk-for-both-shell-chain-rules/a-shell-whose-parent-is-absent-from-the-graph-is-not-reported
//
// TestSuspiciousExecReportsNothingWhenTheChainShellsParentIsAbsent is the second behaviour change in issue #829, and it COSTS a detection
// on purpose.
//
// The temp arm used to fire on a shell whose claimed parent was not in the graph, producing an alert whose parent reads
// "(unknown)". A parent exclusion matches on the parent's PATH, so an operator who had correctly configured one received that
// alert anyway, every time, with no way to suppress it short of disabling the rule.
//
// The chain is DROPPED, not retried, and the trade has to be stated that way: ancestor and parent-chain lookups keep skip
// semantics by design (see the canonical retry requirement), so no later parent record recovers it. What justifies the drop is
// that an alert nobody can silence drives an operator to disable the rule, which loses every detection it makes rather than
// this one. The connect arm already made the same trade.
func TestSuspiciousExecReportsNothingWhenTheChainShellsParentIsAbsent(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// PID 999 is never forked or exec'd, so the shell's claimed parent has no record. PPID > 1, so this is incomplete ancestry
	// rather than the genuine launchd-parented case, which still counts.
	events := []api.Event{
		{EventID: "ab-fork-shell", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":999}`)},
		{EventID: "ab-exec-zsh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/bin/zsh","args":["zsh","-c","/tmp/payload"],"uid":501,"gid":20}`)},
		{EventID: "ab-exec-payload", HostID: "host-a", TimestampNs: 2200, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings,
		"a finding here could only name an unresolved parent, which no parent exclusion can suppress")

	// The decline is RECORDED, which is the difference between a considered trade and a silent hole. A rule that reports nothing
	// because ancestry was incomplete is indistinguishable from a rule with nothing to report, and industry detection-engineering
	// practice names that as how coverage rots unnoticed (issue #829 review). The engine turns this into an attribute on the
	// per-rule span it already labels with rule_id.
	scope := &api.BatchScope{}
	scoped, err := (&SuspiciousExec{}).EvaluateScoped(ctx, scope, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, scoped, "same outcome through the scoped entry point")
	assert.Equal(t, map[string]int{"suspicious_exec": 1}, scope.AncestryIncompleteCounts(),
		"the declined chain is counted against this rule, so the drop is measurable rather than invisible")

	// A plain nil error, NOT the retryable class, which is the whole difference between a skip and a deferral: a nil error lets
	// the processor acknowledge the batch, so the event is never evaluated again and a parent record arriving later does not
	// recover the chain. Asserted rather than assumed, because an earlier draft of this change described it as a recoverable
	// deferral and both review bots caught that it is not (issue #829 review). If a future change makes ancestry retryable, this
	// line is where that decision has to be made deliberately.
	require.NoError(t, err)
	assert.NotErrorIs(t, err, api.ErrRetryBatch,
		"parent-chain lookups keep skip semantics; the retryable class covers the pid an event is about, not its ancestry")
}
