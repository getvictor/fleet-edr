package graph

import (
	"context"

	"github.com/fleetdm/edr/server/store"
)

// ProcessNode is a process with its children and associated network events, used for tree responses.
type ProcessNode struct {
	store.Process
	Children           []ProcessNode `json:"children,omitempty"`
	NetworkConnections []store.Event `json:"network_connections,omitempty"`
	DNSQueries         []store.Event `json:"dns_queries,omitempty"`
}

// ProcessDetail holds a single process with its network activity.
type ProcessDetail struct {
	Process            store.Process `json:"process"`
	NetworkConnections []store.Event `json:"network_connections"`
	DNSQueries         []store.Event `json:"dns_queries"`
	// ReExecChain is the list of prior exec generations on the same PID
	// (issue #10), oldest-first. Empty for processes that only exec'd
	// once after fork — the common case. The UI renders this as a visual
	// chain (python → sh → bash → current) so analysts see the full
	// exec sequence instead of just the final path.
	ReExecChain []store.Process `json:"re_exec_chain,omitempty"`
}

// Query provides process tree and detail lookups.
type Query struct {
	store *store.Store
}

// NewQuery creates a graph query instance.
func NewQuery(s *store.Store) *Query {
	return &Query{store: s}
}

// BuildTree returns a forest of process trees for the given host and time range.
func (q *Query) BuildTree(ctx context.Context, hostID string, tr store.TimeRange, limit int) ([]ProcessNode, error) {
	procs, err := q.store.GetProcessTree(ctx, hostID, tr, limit)
	if err != nil {
		return nil, err
	}

	return buildForest(procs), nil
}

// GetDetail returns a process with its network connections and DNS queries.
func (q *Query) GetDetail(ctx context.Context, hostID string, pid int, atTimeNs int64) (*ProcessDetail, error) {
	proc, err := q.store.GetProcessByPID(ctx, hostID, pid, atTimeNs)
	if err != nil {
		return nil, err
	}
	if proc == nil {
		return nil, nil
	}

	// Build an ingest-time window from the process lifetime. We used to bound
	// by the ES kernel-stamped fork_time_ns with a 5-second pad to compensate
	// for ES/NE clock drift (NE-emitted network_connect events routinely
	// arrived 50-100 ms *before* the ES-emitted fork for the same pid). With
	// issue #7 the events table carries a server-stamped ingested_at_ns, and
	// processes carry fork_ingested_at_ns; we correlate on those instead so
	// the clock is single-authority and monotonic per server. A small 1s pad
	// remains to absorb intra-batch ordering slop.
	const intraBatchPadNs = int64(1 * 1_000_000_000)
	const thirtyDayBoundNs = int64(30 * 86400 * 1_000_000_000)
	var (
		forkAnchorNs int64
		mixedAnchor  bool
	)
	if proc.ForkIngestedAtNs != nil {
		forkAnchorNs = *proc.ForkIngestedAtNs
	} else {
		// Pre-migration row: no server ingest time exists for the fork, so
		// we fall back to the on-host kernel timestamp as an approximate
		// lower bound. The postSchemaMigrations backfill copies fork_time_ns
		// into fork_ingested_at_ns for historical rows, so in steady state
		// this branch only fires during a brief window right after the
		// migration lands. Mark the anchor as mixed so the upper bound
		// doesn't also rely on an ingest-time comparison.
		forkAnchorNs = proc.ForkTimeNs
		mixedAnchor = true
	}
	fromNs := max(forkAnchorNs-intraBatchPadNs, 0)
	tr := store.TimeRange{FromNs: fromNs}
	switch {
	case mixedAnchor:
		// We already lost precision on the lower bound by using a kernel
		// timestamp against an ingest-time predicate; using kernel ExitTimeNs
		// as the upper bound compounds the risk (it can silently truncate
		// network events that landed well after the process exited on-host).
		// Prefer the wide 30-day bound, which is already how still-running
		// processes are handled and matches the pre-issue-7 behavior.
		tr.ToNs = forkAnchorNs + thirtyDayBoundNs
	case proc.ExitIngestedAtNs != nil:
		// Both sides anchored on server-stamped ingest time.
		tr.ToNs = *proc.ExitIngestedAtNs + intraBatchPadNs
	default:
		// Process still running — use a 30-day bound anchored on ingest time.
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

	detail := &ProcessDetail{
		Process:            *proc,
		NetworkConnections: filterByType(netEvents, "network_connect"),
		DNSQueries:         filterByType(netEvents, "dns_query"),
		ReExecChain:        chain,
	}
	return detail, nil
}

// ListHosts delegates to the store.
func (q *Query) ListHosts(ctx context.Context) ([]store.HostSummary, error) {
	return q.store.ListHosts(ctx)
}

// buildForest constructs a tree from a flat list of processes by matching ppid → pid.
// Uses Process.ID as map key to handle PID reuse correctly, and builds parent-child
// links via pointers before converting to value tree so grandchildren aren't lost.
func buildForest(procs []store.Process) []ProcessNode {
	nodeMap, pidToID := indexProcesses(procs)

	// Build parent-child links. Track children as IDs so we can resolve after all links are built.
	childIDs := make(map[int64][]int64) // parentID → child IDs
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

	// Recursively build value tree from the pointer map.
	var build func(id int64) ProcessNode
	build = func(id int64) ProcessNode {
		node := *nodeMap[id]
		for _, childID := range childIDs[id] {
			node.Children = append(node.Children, build(childID))
		}
		return node
	}

	roots := make([]ProcessNode, 0, len(rootIDs))
	for _, id := range rootIDs {
		roots = append(roots, build(id))
	}
	return roots
}

// indexProcesses builds the two lookup tables buildForest needs: nodeMap keyed
// by the unique Process.ID (so PID reuse within a time range doesn't collapse
// rows) and pidToID pointing each OS PID at the row ID of its latest fork (so
// the parent-lookup phase finds the current generation, not a historical one
// with the same PID). Extracted from buildForest so that function stays below
// the cognitive-complexity cap.
func indexProcesses(procs []store.Process) (map[int64]*ProcessNode, map[int]int64) {
	nodeMap := make(map[int64]*ProcessNode, len(procs))
	pidToID := make(map[int]int64, len(procs))
	for i := range procs {
		p := &procs[i]
		nodeMap[p.ID] = &ProcessNode{Process: *p}
		existing, ok := pidToID[p.PID]
		if !ok {
			pidToID[p.PID] = p.ID
			continue
		}
		// nodeMap[existing] was inserted by an earlier iteration (existing is
		// an ID we've already seen), so the lookup is guaranteed non-nil; the
		// explicit guard also makes the invariant visible to static analysis.
		prev, prevOK := nodeMap[existing]
		if prevOK && p.ForkTimeNs > prev.ForkTimeNs {
			pidToID[p.PID] = p.ID
		}
	}
	return nodeMap, pidToID
}

func filterByType(events []store.Event, eventType string) []store.Event {
	var filtered []store.Event
	for _, e := range events {
		if e.EventType == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
