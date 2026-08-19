package graph

import (
	"context"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

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

// BuildTree returns a forest of process trees for the given host and time range, plus the metadata describing what the row limit
// left out (issue #423). Unless flatten is set, repeated identical-path leaf siblings under the same parent are collapsed into a
// single aggregated node (issue #416) so a busy host's grep×1000 / jspawnhelper×240 churn renders as a handful of `×N` nodes rather
// than thousands of dots. flatten opts out and returns the raw forest for an analyst who wants every node.
func (q *Query) BuildTree(
	ctx context.Context, hostID string, tr api.TimeRange, limit int, flatten bool, pinnedID int64,
) (api.ProcessTreeResult, error) {
	procs, err := q.store.GetProcessTree(ctx, hostID, tr, limit)
	if err != nil {
		return api.ProcessTreeResult{}, err
	}

	// Returned counts the ROWS the limit admitted and is captured here, before aggregation: aggregateSiblingsPinned folds identical
	// leaf siblings into "×N" headers, so counting the returned forest's nodes afterwards would report fewer processes than were
	// actually read.
	res := api.ProcessTreeResult{Returned: int64(len(procs)), TotalMatched: int64(len(procs))}

	// The COUNT runs ONLY when the limit actually bound. Fewer rows than the limit proves the limit did not bind, so the rows in
	// hand are every row that matched and the total is already known. This matters because the two queries have very different
	// costs: the row query walks idx_processes_host_time in fork-time order and stops after `limit` rows, while a COUNT has to
	// evaluate every match in the window. Counting unconditionally would turn a limit-bounded read into a full window scan on every
	// tree load, including the overwhelming majority that are nowhere near the cap. The extra scan is now paid only when the read
	// was truncated, which is exactly when the analyst needs the number.
	if len(procs) == limit {
		total, cerr := q.store.CountProcessTree(ctx, hostID, tr)
		if cerr != nil {
			return api.ProcessTreeResult{}, cerr
		}
		// The row read and the count are separate statements, so retention pruning between them can return a total below the rows
		// already in hand. Reporting "showing 2000 of 1998" would be incoherent, so the rows actually read are the floor. The
		// opposite skew (ingest adding rows between the two) needs no guard: a larger total is a truthful denominator.
		res.TotalMatched = max(total, res.Returned)
	}
	res.Truncated = res.Returned < res.TotalMatched

	forest := buildForest(procs)
	if flatten {
		res.Roots = forest
		return res, nil
	}
	res.Roots = aggregateSiblingsPinned(forest, pinnedID)
	return res, nil
}

// flowClockSkewPadNs pads the generation's event-time life before it bounds the identity arm. A flow's event time is stamped by the
// network extension while the process's fork, exec, and exit times come from Endpoint Security, and the two clocks drift (issue #7).
// 5s matches processLookupSkewPadNs, the pad detection's own flow correlation already uses for the same drift.
const flowClockSkewPadNs = int64(5 * 1_000_000_000)

// generationLife renders the generation's EVENT-time life for the identity arm, padded for clock skew. It exists because identity is
// not guaranteed unique: rows written before #715 repeated one pidversion across the generations of a re-exec chain, so without a time
// bound each generation would serve every other generation's flows.
//
// The lower edge is the exec instant when the generation has one, since a re-exec generation cannot have made a flow before the image
// that made it was loaded, and the fork otherwise. A generation still running has no upper edge.
//
// This disambiguates generations separated by more than the pad, which is the case worth fixing. Two generations of a legacy repeated
// pidversion that are microseconds apart still overlap once padded, and a flow inside that overlap can appear on both. That residue is
// inherent: for those rows the wire carried nothing that distinguishes the generations, so no rule over their timestamps can. It is
// still strictly better than the unbounded identity match, where every generation served the whole pid's history.
func generationLife(proc *api.Process) api.TimeRange {
	start := proc.ForkTimeNs
	if proc.ExecTimeNs != nil {
		start = *proc.ExecTimeNs
	}
	life := api.TimeRange{FromNs: max(start-flowClockSkewPadNs, 0), ToNs: math.MaxInt64}
	if proc.ExitTimeNs != nil {
		life.ToNs = *proc.ExitTimeNs + flowClockSkewPadNs
	}
	return life
}

// flowScanBound renders the wide ingest bound that prunes the flow scan. The ceiling is the query time, NOT the process's own start
// plus a span: a process older than that span would match its flows by identity and then have every one of them pruned by a ceiling
// that expired before they were ingested, which silently re-breaks issue #716 for any long-lived daemon or heartbeat-kept snapshot
// record. Nothing can be ingested after now, so now is the honest ceiling, and the row cap rather than the window keeps the read
// bounded. Extracted so the choice is directly testable: a bound derived from process age looks harmless until the process is old.
func flowScanBound(fromNs, nowNs int64) api.TimeRange {
	return api.TimeRange{FromNs: fromNs, ToNs: nowNs}
}

// pidVersionOf widens a process row's kernel pid generation to the int64 the archive filter takes, preserving absence. A row whose
// pidversion is nil predates the field (or lost its audit token), and the nil must survive the conversion: collapsing it to 0 would
// claim generation 0, a real kernel generation, and silently match the wrong flows.
func pidVersionOf(proc *api.Process) *int64 {
	if proc.PIDVersion == nil {
		return nil
	}
	v := int64(*proc.PIDVersion)
	return &v
}

// resolveGeneration picks the process generation a detail read is about. A caller that names pidVersion gets that exact generation;
// a nil pidVersion keeps the historical as-of read, which is what the process tree and the timeline rely on.
//
// Naming the generation is the only way to reach any but the newest member of a re-exec chain (issue #716). insertReExec preserves
// the chain's original fork_time_ns deliberately, so every generation of one chain shares it, and GetProcessByPID's
// (fork_time_ns DESC, id DESC) ordering therefore resolves to the highest id no matter what as-of instant the caller passes. That
// left an exited generation unaddressable even when an alert had fired on it: the panel fetched a sibling and, now that flows are
// attributed by identity, correctly reported none. GetProcessByPIDVersion filters on (host, pid, pidversion) and uses atNs only to
// order, so it returns the named generation when the identity is unique and falls back to the running-at-atNs one when a
// pre-#715 row repeated a pidversion across generations.
func (q *Query) resolveGeneration(ctx context.Context, hostID string, pid int, atTimeNs int64, pidVersion *uint32) (*api.Process, error) {
	if pidVersion != nil {
		return q.store.GetProcessByPIDVersion(ctx, hostID, pid, *pidVersion, atTimeNs)
	}
	return q.store.GetProcessByPID(ctx, hostID, pid, atTimeNs)
}

// GetProcessDetail returns a process with its network connections, DNS queries, and re-exec chain. Method name matches the
// detection/api.Service.GetProcessDetail entry point so the eventual service layer (detection/internal/service) can delegate without
// an adapter or rename. pidVersion is optional and names one generation of pid; see resolveGeneration.
func (q *Query) GetProcessDetail(
	ctx context.Context, hostID string, pid int, atTimeNs int64, pidVersion *uint32,
) (*api.ProcessDetail, error) {
	proc, err := q.resolveGeneration(ctx, hostID, pid, atTimeNs, pidVersion)
	if err != nil {
		return nil, err
	}
	if proc == nil {
		return nil, nil
	}

	// Build an ingest-time window from the process lifetime. We used to bound by the ES kernel-stamped fork_time_ns with a 5-second pad
	// to compensate for ES/NE clock drift (NE-emitted network_connect events routinely arrived 50-100 ms before the ES-emitted fork for
	// the same pid). With issue #7 the events table carries a server-stamped ingested_at_ns, and processes carry fork_ingested_at_ns; we
	// correlate on those instead so the clock is single-authority and monotonic per server.
	//
	// This window is no longer how a flow is attributed when identity is available. Issue #716: the flow and its process's exit travel
	// up the agent uploader in SEPARATE batches, so a short-lived process's flow routinely ingests after the exit (measured 3.5s past
	// the flow's own stamp, 2.0s past the old window's upper bound), and the panel showed "No network activity" for the very connection
	// an alert had fired on. A flow carrying a pidversion is now matched by (pid, pidversion) identity with no window at all, the same
	// way detection's own resolveFlowProcess resolves it. The window survives only for flows that carry no pidversion, where identity
	// cannot speak and it is the only available evidence.
	const intraBatchPadNs = int64(1 * 1_000_000_000)
	// exitedFlowLagPadNs replaces the 1s pad on the upper bound for an exited process. 1s was sized for intra-batch ordering slop
	// within ONE upload; the real gap is between two uploads, so it must cover an agent flush cycle plus its retry backoff rather than
	// a reorder. 60s is well past the 3.5s measured in #716 while staying far below the 30-day open-ended bound. Widening this DOES
	// raise the chance of attributing a legacy flow to the wrong generation of a reused pid, but only for flows carrying no
	// pidversion: every flow from a current agent is now decided by identity before this window is consulted.
	const exitedFlowLagPadNs = int64(60 * 1_000_000_000)
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
		tr.ToNs = *proc.ExitIngestedAtNs + exitedFlowLagPadNs
	default:
		// Process still running: use a 30-day bound anchored on ingest.
		tr.ToNs = forkAnchorNs + thirtyDayBoundNs
	}

	// Bound is deliberately wide: it prunes the scan, it does not attribute. The identity arm must not be constrained by the lifetime
	// window (that is the #716 defect), so the only ceiling an identity match sees is this one.
	//
	// The ceiling is the query time, NOT the process's fork plus a span. Anchoring it on fork age silently re-broke the fix for any
	// process older than that span: a daemon running longer than 30 days, or a heartbeat-kept snapshot row, would match its flows by
	// identity and then have every one of them pruned by a ceiling that expired before they were ingested. Nothing can be ingested
	// after now, so now is the honest ceiling, and the row cap rather than the window is what keeps the read bounded.
	flows, truncated, err := q.store.GetNetworkEventsForGeneration(ctx, api.ProcessFlowFilter{
		HostID:       hostID,
		PID:          pid,
		PIDVersion:   pidVersionOf(proc),
		Bound:        flowScanBound(fromNs, time.Now().UnixNano()),
		IngestWindow: tr,
		Life:         generationLife(proc),
	})
	if err != nil {
		return nil, err
	}
	chain, err := q.store.GetExecChain(ctx, *proc)
	if err != nil {
		return nil, err
	}

	detail := &api.ProcessDetail{
		Process:            *proc,
		NetworkConnections: filterByType(flows, "network_connect"),
		DNSQueries:         filterByType(flows, "dns_query"),
		ReExecChain:        chain,
		FlowsTruncated:     truncated,
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
	return aggregateSiblingsPinned(forest, 0)
}

// aggregateSiblingsPinned is aggregateSiblings with a pinned process id that is never folded into a "×N" group: the alerted process on
// the alert view stays a first-class node so the alert-chain filter and the alert dot can locate it by its real id. Issue #416 gives an
// aggregated header a synthetic negative id (the negation of its representative), which the id-keyed UI paths cannot match, so an alerted
// process with identical siblings would otherwise vanish from its own chain. 0 pins nothing (the plain aggregateSiblings entry point).
func aggregateSiblingsPinned(forest []api.ProcessNode, pinnedID int64) []api.ProcessNode {
	if len(forest) == 0 {
		return forest
	}
	out := make([]api.ProcessNode, 0, len(forest))
	var leaves []api.ProcessNode
	for i := range forest {
		n := forest[i]
		if len(n.Children) > 0 {
			// Non-leaf: keep it individual and recurse so its own children aggregate too.
			n.Children = aggregateSiblingsPinned(n.Children, pinnedID)
			out = append(out, n)
			continue
		}
		leaves = append(leaves, n)
	}
	out = append(out, groupLeaves(leaves, pinnedID)...)
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
func groupLeaves(leaves []api.ProcessNode, pinnedID int64) []api.ProcessNode {
	if len(leaves) == 0 {
		return nil
	}
	// order preserves first-seen key order so grouping is deterministic before the caller's fork-time sort.
	groups := make(map[string][]api.ProcessNode, len(leaves))
	var order []string
	// A pinned leaf (the alerted process) always passes through as its own node, never folded into a "×N" group, so the id-keyed UI
	// paths can still find it. Removing it from its identity group can drop that group below aggregateMinGroup, which then also passes
	// through individually; that is fine (a two-member group with one pinned collapses to two plain nodes).
	var pinned []api.ProcessNode
	for _, n := range leaves {
		if pinnedID != 0 && n.ID == pinnedID {
			pinned = append(pinned, n)
			continue
		}
		k := aggregationKey(n)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], n)
	}
	out := make([]api.ProcessNode, 0, len(order)+len(pinned))
	out = append(out, pinned...)
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
	// The aggregated node carries the earliest member's identity fields (path, hashes, signing) for display, but it is a group
	// header, not that member: the member itself is also in Sample with its real id. Give the header a synthetic negative id (the
	// negation of the representative's real, positive, unique row id) so it can never collide with the sample member it represents,
	// with any other aggregated node, or with a real row id in the UI's id-keyed paths (alert-dot highlighting, find-by-id, the
	// collapse/expand sets). Row ids are auto-increment positive, so the negation is unique and unambiguous.
	rep.ID = -members[0].ID
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

// aggregationKey is the grouping key for sibling aggregation: same parent AND same path AND same content hash AND same code-directory
// hash. PPID is part of the key because the top-level aggregateSiblings call runs over buildForest's roots, and a node lands in that
// root list whenever its real parent is unresolvable in this dataset (parent forked outside the time window, or genuinely absent),
// regardless of the parent PID value. Without PPID in the key, two orphaned top-level leaves with the same binary but distinct
// real parents would fold into one node, erasing the lineage distinction an analyst relies on. For the recursive (non-root) case PPID
// is a no-op: buildForest guarantees a node's children all share its PID as their PPID. sha256 (binary content) and cdhash
// (code-signing directory) stand in for "signing identity" so a path reused by a different binary is not collapsed; a NULL hash
// contributes an empty segment, so two hash-less rows of the same path still group. The NUL separator keeps segments from running
// together (a path ending in a hex-looking suffix cannot collide with a hash).
func aggregationKey(n api.ProcessNode) string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(n.PPID))
	sb.WriteByte(0)
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
