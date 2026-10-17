package graph

import (
	"context"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// BuildScopedTree returns one story or AI agent session as a forest (issue #1282): every row stamped with the scope, read by its
// index in one query, oldest first, rather than walked level by level from a process. A process whose creator is outside the scope
// is a root, so a session reads as its tool calls with their descendants beneath them.
//
// Truncation works as BuildTree's does: one row past the limit proves the page was cut short, and only then does the bounded count
// run. The page keeps the oldest rows, so each process's creator is on it ahead of the process. pinnedID only keeps that process
// out of a sibling aggregate; a scope read adds nothing outside the scope.
func (q *Query) BuildScopedTree(
	ctx context.Context, hostID string, scope api.TreeScope, limit int, flatten bool, pinnedID int64,
) (api.ProcessTreeResult, error) {
	// Clamped as BuildTree clamps it, for the same reasons: the arithmetic below, and a caller that did not normalize.
	limit = min(max(limit, 1), mysql.ProcessTreeCountBound-1)
	procs, err := q.store.GetScopedProcesses(ctx, hostID, scope, limit+1)
	if err != nil {
		return api.ProcessTreeResult{}, err
	}
	truncated := len(procs) > limit
	if truncated {
		procs = procs[:limit]
	}
	res := api.ProcessTreeResult{Returned: int64(len(procs)), TotalMatched: int64(len(procs)), Truncated: truncated}
	if truncated {
		total, capped, err := q.store.CountScopedProcesses(ctx, hostID, scope)
		if err != nil {
			return api.ProcessTreeResult{}, err
		}
		res.TotalMatched, res.TotalMatchedCapped = resolveTotalMatched(res.Returned, total, capped)
	}
	forest := buildForest(procs, nil)
	// A story or session shows what its launchers caused launchd to run, as extra roots the links name (issue #1286).
	links, launched, launchedCut, err := q.launchLinks(ctx, hostID, forest, true)
	if err != nil {
		return api.ProcessTreeResult{}, err
	}
	forest = append(forest, launched...)
	// So does what those apps asked launchd for: the services that name one of them as responsible (issue #1340), the launched apps
	// included, since an app the agent opened is the usual one.
	services, servicesExtra, servicesCut, err := q.serviceLinks(ctx, hostID, forest, true)
	if err != nil {
		return api.ProcessTreeResult{}, err
	}
	forest = append(forest, servicesExtra...)
	links = append(links, services...)
	res.Links = links
	// A launched program's descendants cut at their bound are a partial read like any other.
	res.Truncated = res.Truncated || launchedCut || servicesCut
	if flatten {
		res.Roots = forest
		return res, nil
	}
	res.Roots = aggregateSiblingsKeeping(forest, linkEnds(res.Links, pinnedID))
	return res, nil
}

// maxAgentOwnProcesses bounds an agent's own processes one read lists (issue #1361). An agent runs a few for itself around each prompt;
// thousands are a long life, whose oldest are listed and the read marked as cut.
const maxAgentOwnProcesses = 2000

// BuildAgentOwnTree returns an AI agent process's own descendants forked from fromNs up to toNs (issue #1361): what it ran for
// itself, its plugin scans, shell snapshots and fork daemon among them, with none of a session's processes. They are a forest whose
// roots the agent created, nested by creator as any tree is, and the read reports whether the bound cut it.
func (q *Query) BuildAgentOwnTree(ctx context.Context, hostID string, agentID, fromNs, toNs int64) ([]api.ProcessNode, bool, error) {
	procs, err := q.store.GetAgentOwnProcesses(ctx, hostID, agentID, fromNs, toNs, maxAgentOwnProcesses+1)
	if err != nil {
		return nil, false, err
	}
	truncated := len(procs) > maxAgentOwnProcesses
	if truncated {
		procs = procs[:maxAgentOwnProcesses]
	}
	return buildForest(procs, nil), truncated, nil
}
