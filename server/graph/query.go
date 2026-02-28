package graph

import "github.com/fleetdm/edr/server/store"

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
func (q *Query) BuildTree(hostID string, tr store.TimeRange, limit int) ([]ProcessNode, error) {
	procs, err := q.store.GetProcessTree(hostID, tr, limit)
	if err != nil {
		return nil, err
	}

	return buildForest(procs), nil
}

// GetDetail returns a process with its network connections and DNS queries.
func (q *Query) GetDetail(hostID string, pid int, atTimeNs int64) (*ProcessDetail, error) {
	proc, err := q.store.GetProcessByPID(hostID, pid, atTimeNs)
	if err != nil {
		return nil, err
	}
	if proc == nil {
		return nil, nil
	}

	// Build a time range from the process lifetime.
	tr := store.TimeRange{FromNs: proc.ForkTimeNs}
	if proc.ExitTimeNs != nil {
		tr.ToNs = *proc.ExitTimeNs
	} else {
		// Process still running — use a 30-day bound.
		tr.ToNs = proc.ForkTimeNs + 30*86400_000_000_000
	}

	netEvents, err := q.store.GetNetworkEventsForProcess(hostID, pid, tr)
	if err != nil {
		return nil, err
	}

	detail := &ProcessDetail{
		Process:            *proc,
		NetworkConnections: filterByType(netEvents, "network_connect"),
		DNSQueries:         filterByType(netEvents, "dns_query"),
	}
	return detail, nil
}

// ListHosts delegates to the store.
func (q *Query) ListHosts() ([]store.HostSummary, error) {
	return q.store.ListHosts()
}

// buildForest constructs a tree from a flat list of processes by matching ppid → pid.
// Uses Process.ID as map key to handle PID reuse correctly, and builds parent-child
// links via pointers before converting to value tree so grandchildren aren't lost.
func buildForest(procs []store.Process) []ProcessNode {
	// Key by Process.ID (unique DB row) to handle PID reuse within a time range.
	nodeMap := make(map[int64]*ProcessNode, len(procs))

	// Map PID → latest Process.ID so we can find parents by their OS PID.
	// When multiple records share a PID (reuse), the latest fork wins.
	pidToID := make(map[int]int64, len(procs))

	for i := range procs {
		p := &procs[i]
		nodeMap[p.ID] = &ProcessNode{Process: *p}
		if existing, ok := pidToID[p.PID]; !ok || p.ForkTimeNs > nodeMap[existing].ForkTimeNs {
			pidToID[p.PID] = p.ID
		}
	}

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

func filterByType(events []store.Event, eventType string) []store.Event {
	var filtered []store.Event
	for _, e := range events {
		if e.EventType == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
