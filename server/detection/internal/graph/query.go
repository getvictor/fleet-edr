package graph

import (
	"context"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// Query provides process tree and detail lookups.
type Query struct {
	store *mysql.Store
}

// NewQuery creates a graph query instance.
func NewQuery(s *mysql.Store) *Query {
	return &Query{store: s}
}

// BuildTree returns a forest of process trees for the given host
// and time range.
func (q *Query) BuildTree(ctx context.Context, hostID string, tr api.TimeRange, limit int) ([]api.ProcessNode, error) {
	procs, err := q.store.GetProcessTree(ctx, hostID, tr, limit)
	if err != nil {
		return nil, err
	}
	return buildForest(procs), nil
}

// GetProcessDetail returns a process with its network connections, DNS queries, and re-exec chain. Method name matches the
// detection/api.Service.GetProcessDetail entry point so the eventual service layer (detection/internal/service) can delegate without
// an adapter or rename.
func (q *Query) GetProcessDetail(ctx context.Context, hostID string, pid int, atTimeNs int64) (*api.ProcessDetail, error) {
	proc, err := q.store.GetProcessByPID(ctx, hostID, pid, atTimeNs)
	if err != nil {
		return nil, err
	}
	if proc == nil {
		return nil, nil
	}

	// Build an ingest-time window from the process lifetime. We used to bound by the ES kernel-stamped fork_time_ns with a 5-second pad
	// to compensate for ES/NE clock drift (NE-emitted network_connect events routinely arrived 50-100 ms before the ES-emitted fork for
	// the same pid). With issue #7 the events table carries a server-stamped ingested_at_ns, and processes carry fork_ingested_at_ns; we
	// correlate on those instead so the clock is single-authority and monotonic per server. A small 1s pad remains to absorb intra-batch
	// ordering slop.
	const intraBatchPadNs = int64(1 * 1_000_000_000)
	const thirtyDayBoundNs = int64(30 * 86400 * 1_000_000_000)
	var (
		forkAnchorNs int64
		mixedAnchor  bool
	)
	if proc.ForkIngestedAtNs != nil {
		forkAnchorNs = *proc.ForkIngestedAtNs
	} else {
		// Pre-migration row: no server ingest time exists for the fork, so we fall back to the on-host kernel timestamp as
		// an approximate lower bound. The postSchemaMigrations backfill copies fork_time_ns into fork_ingested_at_ns for
		// historical rows, so in steady state this branch only fires during a brief window right after the migration lands.
		// Mark the anchor as mixed so the upper bound doesn't also rely on an ingest-time comparison.
		forkAnchorNs = proc.ForkTimeNs
		mixedAnchor = true
	}
	fromNs := max(forkAnchorNs-intraBatchPadNs, 0)
	tr := api.TimeRange{FromNs: fromNs}
	switch {
	case mixedAnchor:
		// Already lost precision on the lower bound by using a kernel timestamp against an ingest-time predicate; using kernel
		// ExitTimeNs as the upper bound compounds the risk. Prefer the wide 30-day bound, which is already how still-running
		// processes are handled and matches the pre-issue-7 behavior.
		tr.ToNs = forkAnchorNs + thirtyDayBoundNs
	case proc.ExitIngestedAtNs != nil:
		// Both sides anchored on server-stamped ingest time.
		tr.ToNs = *proc.ExitIngestedAtNs + intraBatchPadNs
	default:
		// Process still running: use a 30-day bound anchored on ingest.
		tr.ToNs = forkAnchorNs + thirtyDayBoundNs
	}

	netEvents, err := q.store.GetNetworkEventsForProcess(ctx, hostID, pid, tr)
	if err != nil {
		return nil, err
	}
	chain, err := q.store.GetExecChain(ctx, *proc)
	if err != nil {
		return nil, err
	}

	detail := &api.ProcessDetail{
		Process:            *proc,
		NetworkConnections: filterByType(netEvents, "network_connect"),
		DNSQueries:         filterByType(netEvents, "dns_query"),
		ReExecChain:        chain,
	}
	return detail, nil
}

// ListHosts delegates to the store.
func (q *Query) ListHosts(ctx context.Context) ([]api.HostSummary, error) {
	return q.store.ListHosts(ctx)
}

// buildForest constructs a tree from a flat list of processes by matching ppid -> pid. Uses Process.ID as map key to handle PID reuse
// correctly, and builds parent-child links via pointers before converting to value tree so grandchildren aren't lost.
func buildForest(procs []api.Process) []api.ProcessNode {
	nodeMap, pidToID := indexProcesses(procs)

	childIDs := make(map[int64][]int64) // parentID -> child IDs
	var rootIDs []int64
	for _, node := range nodeMap {
		parentDBID, parentFound := pidToID[node.PPID]
		if parentFound {
			if _, ok := nodeMap[parentDBID]; ok && parentDBID != node.ID {
				childIDs[parentDBID] = append(childIDs[parentDBID], node.ID)
				continue
			}
		}
		rootIDs = append(rootIDs, node.ID)
	}

	var build func(id int64) api.ProcessNode
	build = func(id int64) api.ProcessNode {
		node := *nodeMap[id]
		for _, childID := range childIDs[id] {
			node.Children = append(node.Children, build(childID))
		}
		return node
	}

	roots := make([]api.ProcessNode, 0, len(rootIDs))
	for _, id := range rootIDs {
		roots = append(roots, build(id))
	}
	return roots
}

// indexProcesses builds the two lookup tables buildForest needs: nodeMap keyed by the unique Process.ID (so PID reuse within a time
// range doesn't collapse rows) and pidToID pointing each OS PID at the row ID of its latest fork (so the parent-lookup phase finds
// the current generation, not a historical one with the same PID). Extracted from buildForest so that function stays below the
// cognitive-complexity cap.
func indexProcesses(procs []api.Process) (map[int64]*api.ProcessNode, map[int]int64) {
	nodeMap := make(map[int64]*api.ProcessNode, len(procs))
	pidToID := make(map[int]int64, len(procs))
	for i := range procs {
		p := &procs[i]
		nodeMap[p.ID] = &api.ProcessNode{Process: *p}
		existing, ok := pidToID[p.PID]
		if !ok {
			pidToID[p.PID] = p.ID
			continue
		}
		prev, prevOK := nodeMap[existing]
		if prevOK && p.ForkTimeNs > prev.ForkTimeNs {
			pidToID[p.PID] = p.ID
		}
	}
	return nodeMap, pidToID
}

func filterByType(events []api.Event, eventType string) []api.Event {
	var filtered []api.Event
	for _, e := range events {
		if e.EventType == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
