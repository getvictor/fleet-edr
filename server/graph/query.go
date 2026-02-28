package graph

import (
	"encoding/json"

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
		// Process still running — use a far-future bound.
		tr.ToNs = proc.ForkTimeNs + 86400_000_000_000 // +24h
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
func buildForest(procs []store.Process) []ProcessNode {
	nodeMap := make(map[int]*ProcessNode, len(procs))
	var roots []ProcessNode

	// Create nodes.
	for _, p := range procs {
		node := ProcessNode{Process: p}
		nodeMap[p.PID] = &node
	}

	// Build parent-child links.
	for _, p := range procs {
		parent, hasParent := nodeMap[p.PPID]
		if hasParent {
			parent.Children = append(parent.Children, *nodeMap[p.PID])
		} else {
			roots = append(roots, *nodeMap[p.PID])
		}
	}

	return roots
}

// hasNetworkActivity checks if a process PID appears in any network event payload.
func hasNetworkActivity(events []store.Event, pid int) bool {
	for _, e := range events {
		var payload struct {
			PID int `json:"pid"`
		}
		if json.Unmarshal(e.Payload, &payload) == nil && payload.PID == pid {
			return true
		}
	}
	return false
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
