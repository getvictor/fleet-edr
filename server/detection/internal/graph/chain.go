package graph

import (
	"context"

	"github.com/fleetdm/edr/server/detection/api"
)

// maxChainDescendants bounds how many processes a chain-scoped read will return below the pinned process. A chain is read to answer
// "what did this do", and a process that spawned more than this is answered better by the host's own forest with its filters than by
// a wall of nodes. It is also the only unbounded direction here: ancestors are bounded by the depth of a process tree, descendants
// are bounded by nothing at all.
const maxChainDescendants = 500

// BuildChainTree returns the pinned process with its ancestors and its descendants, and nothing else.
//
// This is what the alert view actually wants. Asking for the host's forest over a window and filtering to the chain in the client
// reads rows in proportion to how busy the host is, and on a busy host that is both slow and wrong: the read returns the NEWEST rows
// in the window, so everything that ran after the alert fills the page and the chain is not in it (issue #1138). Reading the chain
// directly costs the chain.
//
// There is no count and no truncation of the host's window here, because neither describes anything a chain-scoped read did. The
// only thing that can be cut short is the descendant walk, and that is what Truncated reports.
func (q *Query) BuildChainTree(
	ctx context.Context, hostID string, tr api.TimeRange, pinnedID int64, flatten bool,
) (api.ProcessTreeResult, error) {
	pinned, err := q.store.GetProcessByID(ctx, hostID, pinnedID)
	if err != nil {
		return api.ProcessTreeResult{}, err
	}
	if pinned == nil {
		// The process is gone, pruned by retention while its alert remains. An empty chain is the honest answer: there is no tree
		// to show for a process that is not stored, and inventing the host's forest instead is what this read exists to stop.
		return api.ProcessTreeResult{Roots: []api.ProcessNode{}}, nil
	}

	// Ancestors first, which also gives the resolved parent edges: the forest must link these by identity, because matching on the
	// process number picks the newest row holding it and a recycled number then attaches the chain to a stranger.
	//
	// The row just read is handed over rather than left to be fetched again. Besides saving the second query, it is what makes the
	// walk's "pinned process is gone" path unreachable from here, and that path returns a nil edge map that the descendant walk
	// below writes into.
	procs, resolved, err := q.withPinnedChain(ctx, hostID, []api.Process{*pinned}, pinnedID)
	if err != nil {
		return api.ProcessTreeResult{}, err
	}

	descendants, truncated, err := q.chainDescendants(ctx, hostID, *pinned, tr, resolved)
	if err != nil {
		return api.ProcessTreeResult{}, err
	}
	procs = append(procs, descendants...)

	res := api.ProcessTreeResult{
		Returned:     int64(len(procs)),
		TotalMatched: int64(len(procs)),
		Truncated:    truncated,
	}
	forest := buildForest(procs, resolved)
	if flatten {
		res.Roots = forest
		return res, nil
	}
	res.Roots = aggregateSiblingsPinned(forest, pinnedID)
	return res, nil
}

// chainDescendants walks down from root, breadth first, and reports whether it stopped at the cap.
//
// Every edge the walk crosses is recorded in resolved, because the walk already knows the answer the forest would otherwise have to
// guess. buildForest links a child to its parent by process number, and that guess picks the newest row holding the number: a chain
// containing both a process and the later one that reused its number hangs the child under the wrong one, and the two can even name
// each other, which drops both from the forest entirely. The walk fetched each child FROM its parent, so the edge is a fact here.
func (q *Query) chainDescendants(
	ctx context.Context, hostID string, root api.Process, tr api.TimeRange, resolved map[int64]int64,
) ([]api.Process, bool, error) {
	var out []api.Process
	seen := map[int64]struct{}{root.ID: {}}
	frontier := []api.Process{root}

	for len(frontier) > 0 {
		var next []api.Process
		for _, parent := range frontier {
			children, err := q.childrenOf(ctx, hostID, parent, tr.ToNs)
			if err != nil {
				return nil, false, err
			}
			for _, child := range children {
				if _, dup := seen[child.ID]; dup {
					continue
				}
				seen[child.ID] = struct{}{}
				if len(out) >= maxChainDescendants {
					return out, true, nil
				}
				resolved[child.ID] = parent.ID
				out = append(out, child)
				next = append(next, child)
			}
		}
		frontier = next
	}
	return out, false, nil
}

// childrenOf returns the processes forked by one process during ITS lifetime.
//
// The lifetime bound is what keeps a recycled process number out. A number is reused only once its holder has exited, so a row
// forked after this process exited names whatever took the number next, not this one. A process still running has no successor to be
// confused with, so its bound is the window's own end.
func (q *Query) childrenOf(
	ctx context.Context, hostID string, parent api.Process, windowEndNs int64,
) ([]api.Process, error) {
	until := windowEndNs
	if parent.ExitTimeNs != nil && *parent.ExitTimeNs < until {
		until = *parent.ExitTimeNs
	}
	// A process forked after the window closes leaves until below its own fork time. That needs no branch of its own: the range is
	// then empty and the query matches nothing, which is the answer.
	return q.store.GetChildProcesses(ctx, hostID, parent.PID, api.TimeRange{FromNs: parent.ForkTimeNs, ToNs: until})
}
