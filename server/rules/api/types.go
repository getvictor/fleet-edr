package api

import (
	"context"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
)

// --- Engine input/output types -------------------------------------------------
//
// Aliased to detection/api: detection now owns the canonical Event /
// Process / TimeRange / Finding / GraphReader definitions, and
// rules.api re-exports them as aliases so rules/internal/catalog rule
// files can keep referring to rules.api.Event etc. without import
// churn. The aliases (= keyword) make these the SAME named type at
// the language level, so *detection/internal/mysql.Store satisfies
// rules.api.GraphReader directly and the rule hot path stays
// non-allocating.

type (
	// Event mirrors a row in the events table.
	Event = detectionapi.Event
	// Process mirrors a row in the processes table.
	Process = detectionapi.Process
	// TimeRange is the [start, end] window every graph query takes.
	TimeRange = detectionapi.TimeRange
	// Finding is a per-rule positive output. Detection persists these
	// as alerts via mysql.Store.InsertAlert.
	Finding = detectionapi.Finding
	// GraphReader is the narrow read surface the engine exposes to
	// rules. Audit of the eight production rules confirms these three
	// methods are the entire surface they consume.
	GraphReader = detectionapi.GraphReader
	// NullRawJSON is the json.RawMessage alias that scans MySQL JSON
	// NULL correctly. Used by some rule code-signing helpers
	// (privilege_launchd_plist_write).
	NullRawJSON = detectionapi.NullRawJSON
)

// Severity levels aligned with industry standards (CrowdStrike, MITRE).
// Same constant set as detection/api.Severity*.
const (
	SeverityLow      = detectionapi.SeverityLow
	SeverityMedium   = detectionapi.SeverityMedium
	SeverityHigh     = detectionapi.SeverityHigh
	SeverityCritical = detectionapi.SeverityCritical
)

// --- Catalog types -------------------------------------------------------------

// Rule is a detection that the engine evaluates against a batch of
// events. Concrete rules live in rules/internal/catalog/.
type Rule interface {
	ID() string
	// Techniques returns the MITRE ATT&CK technique IDs the rule maps to
	// (e.g. []string{"T1059.002", "T1105"}). Used for Navigator export +
	// UI badging. Return an empty slice, not nil, for "no mapping".
	Techniques() []string
	// Doc returns the operator-facing documentation for the rule.
	// Surfaces in /docs/detection-rules.md and the UI's per-rule detail
	// page; tools/gen-rule-docs reads it directly. Required (not
	// optional) so a new rule cannot ship without a description and a
	// severity attestation -- the compile error is the gate.
	Doc() Documentation
	// Evaluate runs the rule against a batch of events. Implementations
	// may use gr to walk the historical process graph but must not
	// mutate state. Returning an error skips the rule for this batch
	// (logged at WARN); returning nil findings is the common case.
	Evaluate(ctx context.Context, events []Event, gr GraphReader) ([]Finding, error)
}

// RuleMetadata is the per-rule descriptor the operator endpoints
// render. Used in two surfaces: GET /api/rules (the operator handler
// maps the fields into a JSON-tagged ruleResponse struct, so the
// wire shape lives in rules/internal/operator and isn't on this
// struct) and GET /api/attack-coverage (the handler uses ID +
// Techniques fields directly to build the Navigator layer). The UI's
// RuleDetail.tsx and tools/gen-rule-docs both depend on the wire
// shape, so renaming a field here ripples through both.
type RuleMetadata struct {
	ID         string
	Techniques []string
	Doc        Documentation
}

// Documentation is the structured per-rule descriptor consumed by the
// markdown generator, /api/rules, and the UI's rule detail page.
type Documentation struct {
	// Title is the operator-facing display name (e.g. "Keychain dump").
	// Distinct from ID(): IDs are stable identifiers used in alert rows;
	// titles are the human-readable label rendered in tables and headings.
	Title string `json:"title"`
	// Summary is a one-sentence elevator pitch shown in lists / tooltips.
	Summary string `json:"summary"`
	// Description is the long-form behavioural spec (a few short
	// paragraphs). Plain text; renderers may turn newlines into paragraphs.
	Description string `json:"description"`
	// Severity is the SeverityLow|Medium|High|Critical constant the rule
	// emits. Stored separately from per-finding severities because a
	// single rule always emits a single class today.
	Severity string `json:"severity"`
	// EventTypes lists the agent event types the rule consumes (e.g.
	// "exec", "open_write"). Helps operators decide which ESF/NE
	// subscriptions a minimal deployment must keep enabled.
	EventTypes []string `json:"event_types"`
	// FalsePositives names well-known legitimate sources that can trip
	// the rule. Each entry is one short sentence -- UI renders as a
	// bullet list.
	FalsePositives []string `json:"false_positives,omitempty"`
	// Limitations names known coverage gaps so an operator knows what
	// the rule does NOT catch (atomic renames, env-inherited DYLD vars,
	// etc.).
	Limitations []string `json:"limitations,omitempty"`
	// Config enumerates the env var knobs the rule honours. Empty for
	// rules without configuration (e.g. credential_keychain_dump).
	Config []ConfigKnob `json:"config,omitempty"`
}

// ConfigKnob describes one operator-facing tuning env var.
type ConfigKnob struct {
	// EnvVar is the canonical name (e.g. EDR_LAUNCHAGENT_ALLOWLIST).
	EnvVar string `json:"env_var"`
	// Type tells the operator what value-shape the env var expects:
	// "csv-paths" for absolute filesystem paths, "csv-team-ids" for
	// Apple team-ID strings, "duration" for time.ParseDuration values,
	// etc.
	Type string `json:"type"`
	// Default is the literal value the rule uses when the env var is
	// unset. Empty string means "feature off until configured".
	Default string `json:"default"`
	// Description is one-sentence guidance for what the operator is
	// buying by setting this knob.
	Description string `json:"description"`
}

// RegistryOptions carries the operator-tunable allowlists the eight
// production rules consume at construction. Lifted verbatim from
// today's detection/rules.RegistryOptions; cmd/main threads
// config.Config values into these fields.
type RegistryOptions struct {
	SuspiciousExecParentAllowlist map[string]struct{}
	LaunchAgentAllowlist          map[string]struct{}
	LaunchDaemonTeamIDAllowlist   map[string]struct{}
	SudoersWriterAllowlist        map[string]struct{}
}

// Application control policy types and the wire shape for the
// `set_application_control` agent command are introduced in a follow-on
// phase of the add-application-control change. Phase 1 deletes the
// singleton blocklist scaffolding outright; the typed replacement
// arrives with the new tables and decision engine.
