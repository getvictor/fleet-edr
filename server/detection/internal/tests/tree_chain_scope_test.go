//go:build integration

package tests

import (
	"testing"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A chain-scoped read answers "what did this process do", and costs the chain rather than the host. The window read it replaces
// returns the newest rows in its window, so on a host busy enough to fill a page after the alert the alerted process is not in its
// own page; and even when it is, the page carries everything else that ran that day (issue #1138).
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_returnsTheChainAndNotTheHost(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 12)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	tree, err := env.detection.Service().BuildChainTree(ctx, "h", window, env.payloadID, true)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.Contains(t, paths, "/tmp/payload", "the process the chain was read for")
	assert.Contains(t, paths, "/bin/sh")
	assert.Contains(t, paths, "/usr/bin/python3", "and its ancestors")
	assert.NotContains(t, paths, "/usr/bin/noise", "and none of the host's unrelated activity")
}

// The window read is what this is measured against: same host, same window, and it carries the noise the chain read leaves out.
// Without this the test above could pass on a host that simply had no noise.
func TestBuildChainTree_isNarrowerThanTheWindowRead(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 12)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	whole, err := env.detection.Service().BuildTree(ctx, "h", window, 2000, true, env.payloadID)
	require.NoError(t, err)
	chain, err := env.detection.Service().BuildChainTree(ctx, "h", window, env.payloadID, true)
	require.NoError(t, err)

	assert.Contains(t, flattenPaths(whole.Roots), "/usr/bin/noise", "the window read sees the whole host")
	assert.Less(t, len(flattenPaths(chain.Roots)), len(flattenPaths(whole.Roots)),
		"and the chain read is strictly narrower than it")
}

// A chain read reports no truncation of a host window it never read, so the page's "showing N of M" notice has nothing to say and
// the count behind it never runs.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-reports-no-window-truncation
func TestBuildChainTree_reportsNoWindowTruncation(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 12)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	tree, err := env.detection.Service().BuildChainTree(ctx, "h", window, env.payloadID, true)
	require.NoError(t, err)

	assert.False(t, tree.Truncated, "nothing was cut short")
	assert.False(t, tree.TotalMatchedCapped, "and there is no capped host-wide count to report")
	assert.Equal(t, tree.Returned, tree.TotalMatched, "what it returned is all there was")
}

// Descendants come too: an analyst reading an alert wants what the process spawned, not only what spawned it.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_includesWhatTheProcessSpawned(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 4)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	// Read the chain from the MIDDLE of it: /bin/sh has both an ancestor and a descendant, so one read proves both directions.
	whole, err := env.detection.Service().BuildTree(ctx, "h", window, 2000, true, 0)
	require.NoError(t, err)
	shID := findNodeID(whole.Roots, "/bin/sh")
	require.NotZero(t, shID, "the fixture must contain /bin/sh for this to prove anything")

	tree, err := env.detection.Service().BuildChainTree(ctx, "h", window, shID, true)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.Contains(t, paths, "/usr/bin/python3", "its ancestor")
	assert.Contains(t, paths, "/bin/sh")
	assert.Contains(t, paths, "/tmp/payload", "and what it spawned")
}

// A chain read for a process that is no longer stored returns an empty chain rather than the host's forest. Retention removes
// processes while their alerts remain, and answering with the whole host is exactly the fallback this read exists to remove.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-for-a-missing-process-is-empty
func TestBuildChainTree_aMissingProcessGivesAnEmptyChain(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 4)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	tree, err := env.detection.Service().BuildChainTree(ctx, "h", window, env.payloadID+9_000_000, true)
	require.NoError(t, err)
	assert.Empty(t, tree.Roots, "not the host's forest")
}

// A process's children are the ones forked within ITS lifetime, not everything that ever named its process number. A number is
// reused only after its holder exits, so without that bound the successor's children are handed to the process that held the number
// before them: an analyst reading an alert would be shown activity the alerted process never spawned, attributed to it.
//
// The rows are written directly because the timing is the point: a recycled number with a child needs an exit, a successor and a
// fork placed exactly around each other, which the ingest path will not lay out on request.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_aRecycledProcessNumbersChildrenAreNotTheEarlierHolders(t *testing.T) {
	t.Parallel()
	d, _, db := newDetectionWithDB(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	// pid 900 is held twice. The first holder exits before the second forks, which is the only way a number can be reused.
	var pinned int64
	for _, row := range []struct {
		pid, ppid int
		path      string
		forkNs    int64
		exitNs    *int64
	}{
		{pid: 900, ppid: 1, path: "/reuse/the-alerted-process", forkNs: now, exitNs: ptrInt64(now + 10)},
		{pid: 900, ppid: 1, path: "/reuse/the-successor", forkNs: now + 20},
		{pid: 950, ppid: 900, path: "/reuse/the-successors-child", forkNs: now + 30},
	} {
		res, err := db.ExecContext(ctx, `
			INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, exit_time_ns)
			VALUES ('reuse-host', ?, ?, ?, ?, ?)`, row.pid, row.ppid, row.path, row.forkNs, row.exitNs)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		if row.path == "/reuse/the-alerted-process" {
			pinned = id
		}
	}

	window := api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}
	tree, err := d.Service().BuildChainTree(ctx, "reuse-host", window, pinned, true)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.Contains(t, paths, "/reuse/the-alerted-process")
	assert.NotContains(t, paths, "/reuse/the-successors-child",
		"it forked after the alerted process had exited, so it belongs to whatever took the number next")
}

func ptrInt64(v int64) *int64 { return &v }
