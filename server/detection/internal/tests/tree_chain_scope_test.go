//go:build integration

package tests

import (
	"context"
	"strings"
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

// A chain that contains both a process and the later one that reused its number keeps its shape. The walk fetches each child from
// its parent, so it KNOWS the edge; the forest, left to match on the process number, picks the newest row holding it. Here that
// makes the middle pair name each other as parent, which leaves neither of them a root and drops both from a read that succeeded.
//
// The rows are written directly for the same reason as the recycled-number test above: the reuse has to be placed exactly, with the
// first holder's exit between the child's fork and the successor's.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_aNumberReusedInsideTheChainDoesNotLoseIt(t *testing.T) {
	t.Parallel()
	d, _, db := newDetectionWithDB(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	// pid 200 is held by the alerted process's child, and again by its great-grandchild once the first holder has exited.
	var pinned int64
	for _, row := range []struct {
		pid, ppid int
		path      string
		forkNs    int64
		exitNs    *int64
	}{
		{pid: 100, ppid: 1, path: "/dup/alerted", forkNs: now, exitNs: ptrInt64(now + 9)},
		{pid: 200, ppid: 100, path: "/dup/child", forkNs: now + 1, exitNs: ptrInt64(now + 3)},
		{pid: 300, ppid: 200, path: "/dup/grandchild", forkNs: now + 2},
		// Forked after /dup/child exited, so taking its number is legitimate. It is the NEWEST holder of 200, which is the row a
		// process-number match picks for /dup/grandchild's parent.
		{pid: 200, ppid: 300, path: "/dup/great-grandchild", forkNs: now + 4},
	} {
		res, err := db.ExecContext(ctx, `
			INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, exit_time_ns)
			VALUES ('dup-host', ?, ?, ?, ?, ?)`, row.pid, row.ppid, row.path, row.forkNs, row.exitNs)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		if row.path == "/dup/alerted" {
			pinned = id
		}
	}

	window := api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}
	tree, err := d.Service().BuildChainTree(ctx, "dup-host", window, pinned, true)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.Contains(t, paths, "/dup/grandchild", "the walk reached it, so the forest must emit it")
	assert.Contains(t, paths, "/dup/great-grandchild")
	assert.Len(t, tree.Roots, 1, "and they hang off the alerted process rather than standing alone")
}

// Descendants are capped, and the cap is the ONE thing a chain read reports truncation about. It is also the only direction with no
// natural bound: a chain's ancestors run out at the root of the process tree, and a single process can spawn without limit.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/descendants-are-capped
func TestBuildChainTree_capsDescendantsAndSaysSo(t *testing.T) {
	t.Parallel()
	d, _, db := newDetectionWithDB(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	_, err := db.ExecContext(ctx, `
		INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
		VALUES ('cap-host', 50, 1, '/cap/parent', ?)`, now)
	require.NoError(t, err)
	res, err := db.ExecContext(ctx, `
		INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
		VALUES ('cap-host', 100, 50, '/cap/prolific', ?)`, now)
	require.NoError(t, err)
	pinned, err := res.LastInsertId()
	require.NoError(t, err)

	// Comfortably past the cap, so the walk stops inside the first generation and never needs a second.
	const spawned = 600
	values := make([]string, 0, spawned)
	args := make([]any, 0, spawned*2)
	for i := range spawned {
		values = append(values, "('cap-host', ?, 100, '/cap/spawned', ?)")
		args = append(args, 2000+i, now+int64(i)+1)
	}
	_, err = db.ExecContext(ctx,
		"INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns) VALUES "+strings.Join(values, ","), args...)
	require.NoError(t, err)

	window := api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}
	tree, err := d.Service().BuildChainTree(ctx, "cap-host", window, pinned, true)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.True(t, tree.Truncated, "the walk stopped at the cap, which is the one thing this read truncates")
	// The cap bounds DESCENDANTS, not the result. Ancestors are bounded already by the depth of a process tree, so dropping them to
	// keep a total under the cap would trade the part of the chain that cannot run away for the part that can (#1140 review).
	assert.Contains(t, paths, "/cap/parent", "the ancestor is not what the cap is for")
	assert.Contains(t, paths, "/cap/prolific")
	assert.Less(t, len(paths)-2, spawned, "and the descendants stopped short of everything it spawned")
}

// A process forked after the end of the window has no children to look for inside it. The pinned process is returned whatever the
// window says, because the alert is the reason for the read, but the descendant walk is bounded by the window the caller asked for.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_aWindowEndingBeforeTheProcessForkedHasNoDescendants(t *testing.T) {
	t.Parallel()
	d, _, db := newDetectionWithDB(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	var pinned int64
	for _, row := range []struct {
		pid, ppid int
		path      string
		forkNs    int64
	}{
		{pid: 100, ppid: 1, path: "/late/alerted", forkNs: now},
		{pid: 200, ppid: 100, path: "/late/child", forkNs: now + 1},
	} {
		res, err := db.ExecContext(ctx, `
			INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
			VALUES ('late-host', ?, ?, ?, ?)`, row.pid, row.ppid, row.path, row.forkNs)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		if row.path == "/late/alerted" {
			pinned = id
		}
	}

	// The window closes an hour before either row forked, which is what an analyst does by narrowing the range.
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now - int64(time.Hour)}
	tree, err := d.Service().BuildChainTree(ctx, "late-host", window, pinned, true)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.Contains(t, paths, "/late/alerted", "the alert is still the reason for the read")
	assert.NotContains(t, paths, "/late/child", "but its child forked outside the window the caller asked for")
}

// A row naming its own process number as its parent does not send the walk round forever. The pipeline will not emit this, so the
// row is written directly; the walk's own visited set is what makes it terminate, and it is worth pinning that it does.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_aProcessThatIsItsOwnParentTerminates(t *testing.T) {
	t.Parallel()
	d, _, db := newDetectionWithDB(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	var pinned int64
	for _, row := range []struct {
		pid, ppid int
		path      string
		forkNs    int64
	}{
		{pid: 100, ppid: 100, path: "/self/alerted", forkNs: now},
		{pid: 200, ppid: 100, path: "/self/child", forkNs: now + 1},
	} {
		res, err := db.ExecContext(ctx, `
			INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
			VALUES ('self-host', ?, ?, ?, ?)`, row.pid, row.ppid, row.path, row.forkNs)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		if row.path == "/self/alerted" {
			pinned = id
		}
	}

	window := api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}
	tree, err := d.Service().BuildChainTree(ctx, "self-host", window, pinned, true)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.Contains(t, paths, "/self/alerted")
	assert.Contains(t, paths, "/self/child", "the walk carried on past the self-reference rather than stopping on it")
	// Exactness is the assertion that makes this about the loop rather than about the two rows. A walk that keeps re-visiting the
	// self-parent still emits both paths, because the forest is keyed by row id; what it does instead is run until it hits the
	// descendant cap and report a chain of two processes as truncated.
	assert.Len(t, paths, 2, "and it visited each row once")
	assert.False(t, tree.Truncated, "so it finished rather than running into the cap")
}

// Unflattened is the alert page's actual call: identical leaf siblings collapse into one aggregated node so a process that spawned
// the same helper hundreds of times renders as a handful of nodes. The pinned process is never folded into one of those aggregates.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_unflattenedAggregatesIdenticalSiblings(t *testing.T) {
	t.Parallel()
	d, _, db := newDetectionWithDB(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	res, err := db.ExecContext(ctx, `
		INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
		VALUES ('agg-host', 100, 1, '/agg/alerted', ?)`, now)
	require.NoError(t, err)
	pinned, err := res.LastInsertId()
	require.NoError(t, err)

	const spawned = 6
	for i := range spawned {
		_, err = db.ExecContext(ctx, `
			INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
			VALUES ('agg-host', ?, 100, '/agg/helper', ?)`, 2000+i, now+int64(i)+1)
		require.NoError(t, err)
	}

	window := api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}
	flat, err := d.Service().BuildChainTree(ctx, "agg-host", window, pinned, true)
	require.NoError(t, err)
	aggregated, err := d.Service().BuildChainTree(ctx, "agg-host", window, pinned, false)
	require.NoError(t, err)

	assert.Len(t, flattenPaths(flat.Roots), spawned+1, "flattened, every helper is its own node")
	require.Len(t, aggregated.Roots, 1, "the alerted process is the chain's root")
	require.Len(t, aggregated.Roots[0].Children, 1, "and its identical helpers collapse into a single node")
	agg := aggregated.Roots[0].Children[0].Aggregated
	require.NotNil(t, agg, "which carries the group rather than standing in for one member")
	assert.Equal(t, spawned, agg.Count)
}

// A cancelled read fails rather than returning a partial chain. An analyst who navigates away mid-read must not leave the page
// rendering a tree that stops wherever the cancellation landed.
//
// spec:server-rest-api/an-alert-s-chain-can-be-read-on-its-own/a-chain-read-returns-the-chain-and-nothing-else
func TestBuildChainTree_aCancelledReadIsAnError(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	_, err := env.detection.Service().BuildChainTree(ctx, "h", window, env.payloadID, true)
	require.Error(t, err, "a cancelled read must not present itself as an empty or partial chain")
}

func ptrInt64(v int64) *int64 { return &v }
