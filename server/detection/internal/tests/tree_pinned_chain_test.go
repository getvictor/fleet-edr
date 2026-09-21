//go:build integration

package tests

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tree read is ORDER BY fork_time_ns DESC LIMIT, so it returns the NEWEST rows in the window. An alert opened on a busy host
// therefore asked for a page that could not contain the process the alert was raised on: everything forked after it filled the
// page first. Measured on one real host, 10,321 processes forked after an alert inside that alert's own 24-hour window, which put
// the alerted process about 10,000 rows past the limit, and the page fell back to showing the whole host (issue #1138).
//
// The chain is what these assert on, not just the pinned row. buildForest links ppid to pid within the fetched rows only, so a
// process whose parent missed the page becomes a root: returning the alerted process alone would place it in the tree as an orphan.

// treeChainEnv is the four-generation chain these tests bury: launchd -> python3 -> sh -> /tmp/payload, followed by enough newer
// processes to push the whole chain past a small limit.
type treeChainEnv struct {
	detection  *bootstrap.Detection
	payloadID  int64
	noiseCount int
}

// buryChain ingests the chain, then noiseCount unrelated processes forked AFTER it, and returns the alerted process's row id.
func buryChain(t *testing.T, noiseCount int) *treeChainEnv {
	t.Helper()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	events := []api.Event{
		{EventID: "fork-py", HostID: "h", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "h", TimestampNs: now + 2, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "h", TimestampNs: now + 3, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-pl", HostID: "h", TimestampNs: now + 4, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-pl", HostID: "h", TimestampNs: now + 5, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","uid":501,"gid":20}`)},
	}
	// The noise is forked AFTER the chain and parented to launchd, so it is unrelated to the alert and sorts ahead of every chain
	// row in a newest-first read. This is what a busy host does on its own between an alert and an analyst opening it.
	for i := range noiseCount {
		pid := 1000 + i
		events = append(events,
			api.Event{EventID: fmt.Sprintf("fork-noise-%d", i), HostID: "h", TimestampNs: now + int64(100+i*2), EventType: "fork",
				Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, pid))},
			api.Event{EventID: fmt.Sprintf("exec-noise-%d", i), HostID: "h", TimestampNs: now + int64(101+i*2), EventType: "exec",
				Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":1,"path":"/usr/bin/noise","uid":501,"gid":20}`, pid))},
		)
	}
	insertEventsViaIngest(ctx, t, d, "h", events)

	window := api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}
	var payloadID int64
	require.Eventually(t, func() bool {
		tree, err := d.Service().BuildTree(ctx, "h", window, 10000, true, 0)
		if err != nil {
			return false
		}
		payloadID = findNodeID(tree.Roots, "/tmp/payload")
		return payloadID != 0 && len(flattenPaths(tree.Roots)) >= noiseCount+3
	}, 10*time.Second, 50*time.Millisecond, "expected the chain and its noise to materialise")

	return &treeChainEnv{detection: d, payloadID: payloadID, noiseCount: noiseCount}
}

// findNodeID returns the row id of the first node carrying path, or 0.
func findNodeID(forest []api.ProcessNode, path string) int64 {
	for _, n := range forest {
		if n.Path == path {
			return n.ID
		}
		if id := findNodeID(n.Children, path); id != 0 {
			return id
		}
	}
	return 0
}

// A page that cannot hold the alerted process still holds it when the alert pins it, along with every ancestor back to the root.
// The limit here admits fewer rows than the noise alone, so a read that only honoured the limit returns noise and nothing else.
//
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/the-pinned-process-survives-a-page-of-newer-activity
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/its-ancestors-come-with-it
func TestBuildTree_pinnedProcessAndItsAncestorsSurviveTheRowLimit(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 12)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	// Five rows, against twelve newer noise processes: the chain cannot be in the page on its own merits.
	tree, err := env.detection.Service().BuildTree(ctx, "h", window, 5, true, env.payloadID)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.Contains(t, paths, "/tmp/payload", "the alerted process must be in the page it was pinned into")
	assert.Contains(t, paths, "/bin/sh", "its parent too, or the alerted process is an orphan rather than a chain")
	assert.Contains(t, paths, "/usr/bin/python3", "and every ancestor back to the root")
}

// Without the pin the page is exactly what the limit admits. This is the control: it is what makes the test above evidence that the
// pin did the work, rather than evidence that five rows happened to be enough.
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/without-a-pin-the-limit-still-decides-the-page
func TestBuildTree_withoutAPinTheRowLimitStillDecidesThePage(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 12)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	tree, err := env.detection.Service().BuildTree(ctx, "h", window, 5, true, 0)
	require.NoError(t, err)

	paths := flattenPaths(tree.Roots)
	assert.NotContains(t, paths, "/tmp/payload", "the newest five rows are noise, which is the defect this pins")
	assert.True(t, slices.Contains(paths, "/usr/bin/noise"), "and they are the noise")
}

// Returned keeps describing the page the limit admitted. The pinned chain is added to the forest, not to the page, so the "showing
// N of M" notice goes on saying what the window read did rather than quietly gaining rows the read never admitted.
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/the-counts-still-describe-the-page
func TestBuildTree_theReturnedCountStillDescribesThePage(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 12)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	tree, err := env.detection.Service().BuildTree(ctx, "h", window, 5, true, env.payloadID)
	require.NoError(t, err)

	assert.Equal(t, int64(5), tree.Returned, "the pinned chain is not part of what the limit admitted")
	assert.True(t, tree.Truncated, "and the page is still truncated")
}

// A pinned id naming no row leaves the tree alone rather than failing the read. Retention prunes processes, and an alert outliving
// its process must still render the host's tree instead of an error page.
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/a-pinned-process-that-no-longer-exists-is-not-an-error
func TestBuildTree_aPinnedIDThatNamesNoRowIsNotAnError(t *testing.T) {
	t.Parallel()
	env := buryChain(t, 2)
	ctx := t.Context()
	now := time.Now().UnixNano()
	window := api.TimeRange{FromNs: now - int64(2*time.Hour), ToNs: now + int64(2*time.Hour)}

	tree, err := env.detection.Service().BuildTree(ctx, "h", window, 100, true, env.payloadID+9_000_000)
	require.NoError(t, err)
	assert.NotEmpty(t, tree.Roots, "the host's tree is still worth rendering")
}

// Malformed ancestry does not lose the pinned process. Two rows each naming the other's process number as their parent give the
// forest no root to emit them from, so both vanish: the read succeeds and the alert's own process is simply not in it. The walk
// stops when it meets a process it has already walked and reports that one as the top of the chain, which is what keeps the pair
// reachable. Found by review on #1138.
//
// The rows are written directly because the ingest path cannot produce this: ppid comes from agent fork events, and the pipeline
// will not emit a cycle. A defence against data the product does not generate can only be exercised against data written as if it
// had been.
//
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/the-pinned-process-survives-a-page-of-newer-activity
func TestBuildTree_aLoopingAncestryStillReturnsThePinnedProcess(t *testing.T) {
	t.Parallel()
	d, _, db := newDetectionWithDB(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	now := time.Now().UnixNano()

	// pid 700 claims 800 as its parent and pid 800 claims 700: a cycle by process number.
	ids := make([]int64, 0, 2)
	for _, row := range []struct {
		pid, ppid int
		path      string
		forkNs    int64
	}{
		// The SAME fork instant, which is what makes the cycle reachable at all. A parent must have forked no later than its child,
		// so with distinct fork times one of the two directions is refused on that constraint alone and the walk stops at "no
		// parent" rather than at the loop. Equal times let each stand as the other's parent, which is the state the guard is for.
		{pid: 700, ppid: 800, path: "/loop/a", forkNs: now},
		{pid: 800, ppid: 700, path: "/loop/b", forkNs: now},
	} {
		res, err := db.ExecContext(ctx, `
			INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
			VALUES ('loop-host', ?, ?, ?, ?)`, row.pid, row.ppid, row.path, row.forkNs)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		ids = append(ids, id)
	}

	window := api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}

	// Unpinned, the cycle swallows both rows. This is the control: it is what makes the pinned assertion evidence.
	unpinned, err := d.Service().BuildTree(ctx, "loop-host", window, 100, true, 0)
	require.NoError(t, err)
	assert.Empty(t, flattenPaths(unpinned.Roots), "a cycle leaves the forest with no root to emit from")

	pinned, err := d.Service().BuildTree(ctx, "loop-host", window, 100, true, ids[0])
	require.NoError(t, err)
	assert.Contains(t, flattenPaths(pinned.Roots), "/loop/a", "the pinned process must survive its own malformed ancestry")
}
