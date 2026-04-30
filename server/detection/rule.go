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
	// Doc returns the operator-facing documentation for the rule. Surfaces
	// in /docs/detection-rules.md and the UI's per-rule detail page; the
	// generator at tools/gen-rule-docs reads it directly. Required (not
	// optional) so a new rule cannot ship without a description and a
	// severity attestation — the compile error is the gate.
	Doc() Documentation
	Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]Finding, error)
}

// Documentation is the structured per-rule descriptor consumed by the markdown
// generator, the /api/rules endpoint, and the UI's rule detail page.
// Single source of truth — the markdown file in docs/ is generated from this,
// so behaviour and documentation cannot drift.
type Documentation struct {
	// Title is the operator-facing display name (e.g. "Keychain dump"). Distinct
	// from ID(): IDs are stable identifiers used in alert rows; titles are the
	// human-readable label rendered in tables and headings.
	Title string `json:"title"`
	// Summary is a one-sentence elevator pitch shown in lists / tooltips.
	Summary string `json:"summary"`
	// Description is the long-form behavioural spec (a few short paragraphs).
	// Plain text; renderers may turn newlines into paragraphs.
	Description string `json:"description"`
	// Severity is the SeverityLow|Medium|High|Critical constant the rule emits.
	// Stored separately from per-finding severities because a single rule
	// always emits a single class today; if that ever changes we'll add a
	// `Severities []string` field.
	Severity string `json:"severity"`
	// EventTypes lists the agent event types the rule consumes (e.g. "exec",
	// "open_write"). Helps operators decide which ESF/NE subscriptions a
	// minimal deployment must keep enabled.
	EventTypes []string `json:"event_types"`
	// FalsePositives names well-known legitimate sources that can trip the
	// rule. Each entry is one short sentence — UI renders as a bullet list.
	FalsePositives []string `json:"false_positives,omitempty"`
	// Limitations names known coverage gaps so an operator knows what the
	// rule does NOT catch (atomic renames, env-inherited DYLD vars, etc.).
	Limitations []string `json:"limitations,omitempty"`
	// Config enumerates the env var knobs the rule honours. Empty for rules
	// without configuration (e.g. credential_keychain_dump).
	Config []ConfigKnob `json:"config,omitempty"`
}

// ConfigKnob describes one operator-facing tuning env var.
type ConfigKnob struct {
	// EnvVar is the canonical name (e.g. EDR_LAUNCHAGENT_ALLOWLIST).
	EnvVar string `json:"env_var"`
	// Type tells the operator what value-shape the env var expects:
	// "csv-paths" for absolute filesystem paths, "csv-team-ids" for Apple
	// team-ID strings, "duration" for time.ParseDuration values, etc.
	Type string `json:"type"`
	// Default is the literal value the rule uses when the env var is unset.
	// Empty string means "feature off until configured".
	Default string `json:"default"`
	// Description is one-sentence guidance for what the operator is buying
	// by setting this knob.
	Description string `json:"description"`
}
