// Package detection provides the rule engine for evaluating event batches and generating alerts.
package detection

import (
	"context"

	"github.com/fleetdm/edr/server/store"
)

// Severity levels aligned with industry standards (CrowdStrike, MITRE).
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding represents a detection finding before it is persisted as an alert.
type Finding struct {
	HostID      string
	RuleID      string
	Severity    string
	Title       string
	Description string
	ProcessID   int64    // references processes.id
	EventIDs    []string // triggering event_ids
	// Techniques lists MITRE ATT&CK technique IDs (e.g. "T1059.002") the
	// finding maps to. Populated by the engine from Rule.Techniques() at
	// evaluate time so rule authors own the mapping and it survives even
	// when the rule metadata is later refined — the historical alert keeps
	// the techniques it fired under. Empty is legal for rules that don't
	// map to the matrix cleanly; procurement tools will sort those to the
	// bottom of coverage reports.
	Techniques []string
}

// Rule evaluates a batch of events against a detection pattern.
// The store is provided for historical lookups (process tree, prior events).
type Rule interface {
	ID() string
	// Techniques returns the MITRE ATT&CK technique IDs the rule maps to
	// (e.g. []string{"T1059.002", "T1105"}). Used for Navigator export + UI
	// badging. Return an empty slice, not nil, for "no mapping".
	Techniques() []string
	Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]Finding, error)
}
