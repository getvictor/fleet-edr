package graph

import (
	"testing"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildForest matches a child to its parent by process number, keeping the NEWEST row holding that number. That is the right guess
// when the page is all the evidence there is, and the wrong answer once a caller has resolved a specific generation deliberately:
// on a host that recycled the number, the child would be hung under a later process it never ran under, and the resolved ancestor
// left dangling as a root. Found by review on #1138.
//
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/its-ancestors-come-with-it
func TestBuildForest_aResolvedParentBeatsARecycledProcessNumber(t *testing.T) {
	t.Parallel()
	// pid 500 is held twice: the generation the child actually ran under (id 10, older) and a later one (id 30). The page carries
	// both, as a window read on a busy host does.
	oldParent := api.Process{ID: 10, PID: 500, PPID: 1, Path: "/the/real/parent", ForkTimeNs: 100}
	newParent := api.Process{ID: 30, PID: 500, PPID: 1, Path: "/a/recycled/number", ForkTimeNs: 900}
	child := api.Process{ID: 20, PID: 600, PPID: 500, Path: "/the/child", ForkTimeNs: 200}

	// Without a resolved edge the number decides, and the number points at the newest row.
	plain := buildForest([]api.Process{oldParent, newParent, child}, nil)
	assert.Equal(t, "/a/recycled/number", parentPathOf(t, plain, 20),
		"the unresolved case is what the resolved edge has to beat")

	// With the edge the caller resolved, the child hangs under the generation it actually ran under.
	resolved := buildForest([]api.Process{oldParent, newParent, child}, map[int64]int64{20: 10})
	assert.Equal(t, "/the/real/parent", parentPathOf(t, resolved, 20))
}

// A resolved edge naming a row that is not in the page leaves the child a root rather than dropping it.
func TestBuildForest_aResolvedParentThatIsNotInThePageLeavesTheChildARoot(t *testing.T) {
	t.Parallel()
	child := api.Process{ID: 20, PID: 600, PPID: 500, Path: "/the/child", ForkTimeNs: 200}
	forest := buildForest([]api.Process{child}, map[int64]int64{20: 999})
	require.Len(t, forest, 1)
	assert.Equal(t, "/the/child", forest[0].Path)
}

// parentPathOf returns the path of the node whose children include childID, or "" when childID is a root.
func parentPathOf(t *testing.T, forest []api.ProcessNode, childID int64) string {
	t.Helper()
	var found string
	var walk func(nodes []api.ProcessNode, parentPath string)
	walk = func(nodes []api.ProcessNode, parentPath string) {
		for _, n := range nodes {
			if n.ID == childID {
				found = parentPath
			}
			walk(n.Children, n.Path)
		}
	}
	walk(forest, "")
	return found
}

// A chain whose ancestry loops still emits. The walk stops when it meets a process it has already walked and reports that node as
// the top of the chain; without that, both members match each other by process number, neither is a root, and the forest emits
// NEITHER, so the pinned process disappears from a read that completed successfully. Found by review on #1138.
//
// The edge map here is exactly what withPinnedChain produces for a two-row loop: one resolved parent, and the node it stopped at
// pinned as a root.
//
// spec:server-rest-api/a-pinned-process-is-in-the-page-with-its-ancestors/the-pinned-process-survives-a-page-of-newer-activity
func TestBuildForest_aLoopingAncestryStillEmitsThePinnedProcess(t *testing.T) {
	t.Parallel()
	// Each claims the other as its parent, which is what malformed ppid data looks like.
	a := api.Process{ID: 10, PID: 500, PPID: 600, Path: "/a", ForkTimeNs: 100}
	b := api.Process{ID: 20, PID: 600, PPID: 500, Path: "/b", ForkTimeNs: 200}

	// Matching on the process number alone: both get a parent, neither is a root, and the forest is empty.
	plain := buildForest([]api.Process{a, b}, nil)
	assert.Empty(t, plain, "the loop with no resolved edges is what this has to survive")

	// What the walk produces: a is the pinned process, b is its resolved parent, and b is the top it stopped at.
	withEdges := buildForest([]api.Process{a, b}, map[int64]int64{10: 20, 20: 0})
	require.Len(t, withEdges, 1, "the top of the walked chain is the one root")
	assert.Equal(t, "/b", withEdges[0].Path)
	require.Len(t, withEdges[0].Children, 1)
	assert.Equal(t, "/a", withEdges[0].Children[0].Path, "the pinned process is in the forest")
}
