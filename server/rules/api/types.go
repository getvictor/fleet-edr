package api

import (
	"context"
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

// --- Application Control types -----------------------------------------------
//
// The application control subsystem replaces the legacy singleton
// blocklist. These types live on the public surface of rules/api so
// the server-side REST handlers, the agent command codec, and the
// extension snapshot loader can all reference one canonical shape
// without importing each other.

// DefaultPolicyName is the name of the per-tenant policy seeded at
// bootstrap. Created empty; admins add rules to it via the REST
// surface. Multi-policy support is on the post-demo backlog; for
// the demo cut every tenant has exactly one policy with this name.
const DefaultPolicyName = "Default"

// RuleType is the wire-shape identifier of an application-control
// rule's matching dimension. The schema's `rule_type` ENUM mirrors
// this set. In the demo cut only BINARY is enforced; the other five
// values exist on the type so the column accepts them when their
// validators come online.
type RuleType string

const (
	// RuleTypeCDHash matches against the signed Code Directory hash.
	// 40 lowercase hex characters; only honored for hardened-runtime
	// processes per the spec.
	RuleTypeCDHash RuleType = "CDHASH"
	// RuleTypeBinary matches against the SHA-256 of the executable
	// file. 64 lowercase hex characters. The only type the demo cut
	// enforces.
	RuleTypeBinary RuleType = "BINARY"
	// RuleTypeSigningID matches against `<TeamID>:<bundle.id>` or
	// `platform:<bundle.id>` for Apple platform binaries.
	RuleTypeSigningID RuleType = "SIGNINGID"
	// RuleTypeCertificate matches against the SHA-256 of the leaf
	// X.509 signing certificate. 64 lowercase hex characters.
	RuleTypeCertificate RuleType = "CERTIFICATE"
	// RuleTypeTeamID matches against the 10-character Apple Developer
	// Team ID, e.g. `EQHXZ8M8AV`.
	RuleTypeTeamID RuleType = "TEAMID"
	// RuleTypePath matches against the canonical absolute filesystem
	// path of the exec target.
	RuleTypePath RuleType = "PATH"
)

// Action is the verb a matched rule applies. The demo cut and the
// rest of Phase A constrain this to BLOCK; ALLOW and SILENT_BLOCK
// arrive with the Lockdown change. Stable wire-shape string; renaming
// is a contract break.
type Action string

const (
	ActionBlock Action = "BLOCK"
)

// Enforcement is the rule's audit-vs-enforce switch. The column is
// reserved in this phase: every rule runs as PROTECT. The DETECT
// semantic (log the would-be decision but allow the exec) arrives
// with the Lockdown change.
type Enforcement string

const (
	EnforcementProtect Enforcement = "PROTECT"
	EnforcementDetect  Enforcement = "DETECT"
)

// Severity classifies the alert that a triggered rule produces.
// Aligned with the existing alert severities (Severity* constants
// above) so a Sonar / Codecov / SIEM operator sees a unified scale
// across detection rules and application-control rules.
type Severity string

const (
	SeverityRuleLow      Severity = "low"
	SeverityRuleMedium   Severity = "medium"
	SeverityRuleHigh     Severity = "high"
	SeverityRuleCritical Severity = "critical"
)

// Source records where a rule came from. `admin` is the human-edited
// case the demo exercises; `imported` is a Santa StaticRules import
// (post-demo); `intel` is a threat-intel feed entry (post-demo).
type Source string

const (
	SourceAdmin    Source = "admin"
	SourceImported Source = "imported"
	SourceIntel    Source = "intel"
)

// PolicyDefaultAction is the policy-level fallback verdict when no
// rule matches. Constrained to NONE in this phase (default-allow);
// the Lockdown change extends the enum with BLOCK so admins can flip
// a policy to default-deny.
type PolicyDefaultAction string

const (
	PolicyDefaultActionNone PolicyDefaultAction = "NONE"
)

// ApplicationControlPolicy mirrors a row in app_control_policies.
// Used by the REST surface for list/get responses and by the
// fan-out code when constructing the `set_application_control`
// agent command. Rules is populated by GetWithRules and the rule
// listing endpoints; bare Get omits it.
type ApplicationControlPolicy struct {
	ID            int64                    `json:"id"`
	TenantID      string                   `json:"tenant_id"`
	Name          string                   `json:"name"`
	Description   string                   `json:"description"`
	Version       int64                    `json:"version"`
	DefaultAction PolicyDefaultAction      `json:"default_action"`
	CreatedAt     time.Time                `json:"created_at"`
	UpdatedAt     time.Time                `json:"updated_at"`
	CreatedBy     string                   `json:"created_by"`
	UpdatedBy     string                   `json:"updated_by"`
	Rules         []ApplicationControlRule `json:"rules,omitempty"`
}

// ApplicationControlRule mirrors a row in app_control_rules.
type ApplicationControlRule struct {
	ID          int64       `json:"id"`
	PolicyID    int64       `json:"policy_id"`
	RuleType    RuleType    `json:"rule_type"`
	Identifier  string      `json:"identifier"`
	Action      Action      `json:"action"`
	Enforcement Enforcement `json:"enforcement"`
	Enabled     bool        `json:"enabled"`
	Severity    Severity    `json:"severity"`
	Source      Source      `json:"source"`
	SourceRef   string      `json:"source_ref,omitempty"`
	CustomMsg   *string     `json:"custom_msg,omitempty"`
	CustomURL   *string     `json:"custom_url,omitempty"`
	Comment     string      `json:"comment,omitempty"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	CreatedBy   string      `json:"created_by"`
}

// CreateRuleRequest carries the operator-supplied fields for a new
// rule. The server fills in `Enabled=true`, `Action=BLOCK`,
// `Enforcement=PROTECT`, `Source=admin`, `CreatedBy=<session user>`
// and timestamps. Severity defaults to medium when blank.
type CreateRuleRequest struct {
	PolicyID   int64
	RuleType   RuleType
	Identifier string
	CustomMsg  *string
	CustomURL  *string
	Comment    string
	Severity   Severity
	Actor      string
	Reason     string
}

// Application Control validation errors. Mapped to HTTP 400 by the
// REST handlers via IsApplicationControlValidationError.
var (
	// ErrAppControlPolicyNotFound is returned when the named policy
	// row does not exist for the tenant.
	ErrAppControlPolicyNotFound = errors.New("rules: application control policy not found")

	// ErrAppControlInvalidRuleType is returned when the rule_type is
	// not one of the documented enum values. Distinct from
	// ErrAppControlUnsupportedRuleType (which is the demo-cut signal
	// that the type is on the enum but not yet wired through
	// validation and decisioning).
	ErrAppControlInvalidRuleType = errors.New("rules: invalid application control rule type")

	// ErrAppControlUnsupportedRuleType is returned when the rule_type
	// is on the enum but the demo cut hasn't wired its validator and
	// decision-engine branch yet. Lifts as the remaining types come
	// online; the constant stays as the named error so callers can
	// errors.Is on it without breaking when the message changes.
	ErrAppControlUnsupportedRuleType = errors.New("rules: rule type not yet supported")

	// ErrAppControlInvalidIdentifier is returned when the identifier
	// does not match the format required by its rule_type (e.g. a
	// BINARY identifier that isn't 64 lowercase hex characters).
	ErrAppControlInvalidIdentifier = errors.New("rules: invalid application control rule identifier")

	// ErrAppControlInvalidSeverity is returned when the severity is
	// not one of low/medium/high/critical.
	ErrAppControlInvalidSeverity = errors.New("rules: invalid application control rule severity")

	// ErrAppControlInvalidRequest is returned when a request is
	// missing required fields (e.g. empty actor or reason on a
	// state-changing call). Distinct from the identifier-shape
	// errors above so audit logs can tell them apart.
	ErrAppControlInvalidRequest = errors.New("rules: invalid application control request")

	// ErrAppControlDuplicateRule is returned when a rule with the
	// same (policy_id, rule_type, identifier) already exists. Mapped
	// to HTTP 409 by the REST handlers so the client can dedup
	// idempotent retries cleanly.
	ErrAppControlDuplicateRule = errors.New("rules: application control rule already exists")
)

// IsApplicationControlValidationError reports whether err is one of
// the validation errors that the REST handlers map to HTTP 400. The
// duplicate-rule and not-found errors are NOT in this set because
// they map to different HTTP codes; callers handle those explicitly.
func IsApplicationControlValidationError(err error) bool {
	return errors.Is(err, ErrAppControlInvalidRuleType) ||
		errors.Is(err, ErrAppControlUnsupportedRuleType) ||
		errors.Is(err, ErrAppControlInvalidIdentifier) ||
		errors.Is(err, ErrAppControlInvalidSeverity) ||
		errors.Is(err, ErrAppControlInvalidRequest)
}
