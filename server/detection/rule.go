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
}

// Rule evaluates a batch of events against a detection pattern.
// The store is provided for historical lookups (process tree, prior events).
type Rule interface {
	ID() string
	Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]Finding, error)
}
