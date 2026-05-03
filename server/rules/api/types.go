package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

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

// --- Policy types --------------------------------------------------------------

// DefaultPolicyName is the singleton policy row name. v1.1 will add
// targeted policies (per team / per host group); for MVP this is the
// only name production code uses.
const DefaultPolicyName = "default"

// BlocklistPolicy mirrors a row in the policies table. Field tags
// preserve today's policy.Policy wire shape so /api/policy is
// byte-identical with main.
type BlocklistPolicy struct {
	Name      string    `json:"name"`
	Version   int64     `json:"version"`
	Blocklist Blocklist `json:"blocklist"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// Blocklist is the subject of policy pushes. Paths is a sorted,
// deduplicated list of absolute filesystem paths the extension should
// DENY under AUTH_EXEC. Hashes is a sorted, deduplicated list of
// lowercase hex SHA-256 strings (extension-side hashing is still a
// v1.1 feature, but the wire contract is future-proof).
type Blocklist struct {
	Paths  []string `json:"paths"`
	Hashes []string `json:"hashes"`
}

// UpdateRequest carries the new blocklist plus the actor performing
// the change. The actor ends up in updated_by and in the audit log;
// it must be non-empty.
type UpdateRequest struct {
	Name   string
	Paths  []string
	Hashes []string
	Actor  string
}

// SetBlocklistPayload is the wire shape the agent's commander decodes
// for set_blocklist commands. Field names mirror what
// extension/PolicyStore expects; this is part of the agent contract
// and is byte-identical with today's admin.policyCommandPayload.
// Lives in api/ so endpoint can receive it pre-marshaled at enroll
// time without importing rules internals.
type SetBlocklistPayload struct {
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	Paths   []string `json:"paths"`
	Hashes  []string `json:"hashes"`
}

// CommandTypeSetBlocklist is the well-known command type the agent
// reads on every poll. Exposed here (not buried in internal) because
// endpoint, response, and rules all reference it; the constant is the
// boundary between rules's domain and the response queue.
const CommandTypeSetBlocklist = "set_blocklist"

// --- Errors --------------------------------------------------------------------

var (
	// ErrPolicyNotFound is returned when the requested policy row is
	// missing. Operationally treat as a fresh-database anomaly:
	// schema.go seeds the default row.
	ErrPolicyNotFound = errors.New("rules: policy not found")

	// ErrInvalidPath is returned by Update when a path entry is not an
	// absolute filesystem path. Mapped to 400 by the operator handler.
	ErrInvalidPath = errors.New("rules: invalid blocklist path")

	// ErrInvalidHash is returned by Update when a hash entry is not a
	// 64-char lowercase hex string. Mapped to 400 by the operator
	// handler.
	ErrInvalidHash = errors.New("rules: invalid blocklist hash")

	// ErrInvalidUpdateRequest is returned for body-shape problems:
	// missing name or actor. Distinct from ErrInvalidPath /
	// ErrInvalidHash which describe blocklist content errors. Mapped
	// to 400.
	ErrInvalidUpdateRequest = errors.New("rules: invalid update request")
)

// IsValidationError reports whether err is one of the public 4xx-mapped
// validation errors (path / hash / update-request shape). Useful to
// callers that don't want to wire a triple errors.Is in their handler.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidPath) ||
		errors.Is(err, ErrInvalidHash) ||
		errors.Is(err, ErrInvalidUpdateRequest)
}

// MarshalSetBlocklistPayload returns the JSON bytes the agent's
// commander expects for a set_blocklist command. Hoisted to a public
// helper so endpoint can build the same payload at enroll time
// without re-deriving the field shape. Returns an error only if the
// json package fails to marshal a struct of plain types -- in
// practice a "this never happens" path that callers still propagate.
func MarshalSetBlocklistPayload(p BlocklistPolicy) (json.RawMessage, error) {
	return json.Marshal(SetBlocklistPayload{
		Name:    p.Name,
		Version: p.Version,
		Paths:   p.Blocklist.Paths,
		Hashes:  p.Blocklist.Hashes,
	})
}
