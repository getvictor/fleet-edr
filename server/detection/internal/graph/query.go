package graph

import (
	"context"
	"slices"
	"strings"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// aggregateMinGroup is the smallest identical-path sibling group that collapses into a single `×N` node (issue #416). At 2, any pair
// of repeated childless execs under one parent already aggregates, which is what the acceptance criteria ("a parent that spawned N
// identical-path children renders as one node") asks for; a singleton group stays an ordinary node.
const aggregateMinGroup = 2

// aggregateSampleCap bounds how many underlying members an aggregated node carries inline so the UI can expand the group in place
// without a second round trip. The point of aggregation is to shrink the payload, so the sample is deliberately small; the full
// per-member fetch is the lazy-expand story (#421). A group of grep×1000 ships one node plus this many rows, not a thousand.
const aggregateSampleCap = 8

// Query provides process tree and detail lookups.
type Query struct {
	store *mysql.Store
}

// NewQuery creates a graph query instance.
func NewQuery(s *mysql.Store) *Query {
	return &Query{store: s}
}

// BuildTree returns a forest of process trees for the given host and time range. Unless flatten is set, repeated identical-path leaf
// siblings under the same parent are collapsed into a single aggregated node (issue #416) so a busy host's grep×1000 / jspawnhelper×240
// churn renders as a handful of `×N` nodes rather than thousands of dots. flatten opts out and returns the raw forest for an analyst
// who wants every node.
func (q *Query) BuildTree(ctx context.Context, hostID string, tr api.TimeRange, limit int, flatten bool) ([]api.ProcessNode, error) {
	procs, err := q.store.GetProcessTree(ctx, hostID, tr, limit)
	if err != nil {
		return nil, err
	}
	forest := buildForest(procs)
	if flatten {
		return forest, nil
	}
	return aggregateSiblings(forest), nil
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

// aggregateSiblings collapses repeated identical-path leaf siblings under each parent into a single aggregated node (issue #416),
// recursively over the whole forest. It is a pure transform: the input forest is never mutated, and the total number of underlying
// processes is preserved (the sum of each aggregated node's Count plus one per individual node equals the input leaf count at every
// level).
//
// Only leaf children (no children of their own) are eligible to fold: a child that has its own subtree stays an individual node so
// its descendants are never silently dropped before the lazy-expand story (#421) can re-fetch them. Grouping is keyed on the binary
// identity (path + sha256 + cdhash), so two execs of the same path but different binaries are not merged. A group below
// aggregateMinGroup stays individual (a `×1` badge would be noise). Output siblings are ordered by first fork time (then row id) so
// the result is deterministic regardless of the map-iteration order buildForest produced.
func aggregateSiblings(forest []api.ProcessNode) []api.ProcessNode {
	if len(forest) == 0 {
		return forest
	}
	out := make([]api.ProcessNode, 0, len(forest))
	var leaves []api.ProcessNode
	for i := range forest {
		n := forest[i]
		if len(n.Children) > 0 {
			// Non-leaf: keep it individual and recurse so its own children aggregate too.
			n.Children = aggregateSiblings(n.Children)
			out = append(out, n)
			continue
		}
		leaves = append(leaves, n)
	}
	out = append(out, groupLeaves(leaves)...)
	slices.SortFunc(out, func(a, b api.ProcessNode) int {
		if d := nodeFirstForkNs(a) - nodeFirstForkNs(b); d != 0 {
			return int(min(max(d, -1), 1))
		}
		return int(min(max(a.ID-b.ID, -1), 1))
	})
	return out
}

// groupLeaves partitions leaf siblings by binary identity and folds every group of at least aggregateMinGroup members into one
// aggregated node; smaller groups pass through unchanged. Group order within the returned slice is not significant: aggregateSiblings
// re-sorts the merged output by fork time.
func groupLeaves(leaves []api.ProcessNode) []api.ProcessNode {
	if len(leaves) == 0 {
		return nil
	}
	// order preserves first-seen key order so grouping is deterministic before the caller's fork-time sort.
	groups := make(map[string][]api.ProcessNode, len(leaves))
	var order []string
	for _, n := range leaves {
		k := aggregationKey(n)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], n)
	}
	out := make([]api.ProcessNode, 0, len(order))
	for _, k := range order {
		members := groups[k]
		if len(members) < aggregateMinGroup {
			out = append(out, members...)
			continue
		}
		out = append(out, aggregateGroup(members))
	}
	return out
}

// aggregateGroup builds one aggregated node from a group of identical-identity leaf members (len >= aggregateMinGroup). The earliest
// member (by fork time, then id) is the representative whose Process fields the node carries; the summary counts and fork-time span
// cover the full group, and Sample is the first aggregateSampleCap members in fork order.
func aggregateGroup(members []api.ProcessNode) api.ProcessNode {
	slices.SortFunc(members, func(a, b api.ProcessNode) int {
		if a.ForkTimeNs != b.ForkTimeNs {
			return int(min(max(a.ForkTimeNs-b.ForkTimeNs, -1), 1))
		}
		return int(min(max(a.ID-b.ID, -1), 1))
	})
	agg := &api.AggregatedSiblings{
		Count:       len(members),
		FirstForkNs: members[0].ForkTimeNs,
		LastForkNs:  members[len(members)-1].ForkTimeNs,
	}
	for i := range members {
		if members[i].ExitTimeNs != nil {
			agg.ExitedCount++
		} else {
			agg.RunningCount++
		}
	}
	sampleN := min(len(members), aggregateSampleCap)
	agg.Sample = make([]api.ProcessNode, sampleN)
	copy(agg.Sample, members[:sampleN])

	rep := members[0]
	rep.Children = nil
	rep.NetworkConnections = nil
	rep.DNSQueries = nil
	rep.Aggregated = agg
	return rep
}

// nodeFirstForkNs returns the fork time an aggregated node sorts on: the group's earliest fork for a collapsed node, the row's own
// fork time otherwise.
func nodeFirstForkNs(n api.ProcessNode) int64 {
	if n.Aggregated != nil {
		return n.Aggregated.FirstForkNs
	}
	return n.ForkTimeNs
}

// aggregationKey is the binary-identity grouping key for sibling aggregation: same path AND same content hash AND same code-directory
// hash. sha256 (binary content) and cdhash (code-signing directory) stand in for "signing identity" so a path reused by a different
// binary is not collapsed; a NULL hash contributes an empty segment, so two hash-less rows of the same path still group. The NUL
// separator keeps segments from running together (a path ending in a hex-looking suffix cannot collide with a hash).
func aggregationKey(n api.ProcessNode) string {
	var sb strings.Builder
	sb.WriteString(n.Path)
	sb.WriteByte(0)
	if n.SHA256 != nil {
		sb.WriteString(*n.SHA256)
	}
	sb.WriteByte(0)
	if n.CDHash != nil {
		sb.WriteString(*n.CDHash)
	}
	return sb.String()
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
