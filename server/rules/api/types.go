package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// GraphReader is the narrow read surface the engine exposes to rules: six methods, the entire graph surface the production rules
	// consume. The count is load-bearing rather than trivia, because the engine wraps every one of them to make a failed read
	// retryable (issue #798), and a method missing from that wrapper loses detections silently.
	GraphReader = detectionapi.GraphReader
	// NullRawJSON is the json.RawMessage alias that scans MySQL JSON NULL correctly. Used by some rule code-signing helpers
	// (privilege_launchd_plist_write).
	NullRawJSON = detectionapi.NullRawJSON
)

// MaxRuleIDLen is the longest rule identifier the system accepts, and the width every column that stores one is declared at.
//
// ONE definition on purpose. Before this existed, four independent VARCHAR(64) literals in two contexts were the only statement of
// the limit and nothing validated against them, so when #764 imported a corpus whose identifiers come from upstream filenames, the
// 70-character proc_creation_macos_remote_access_tools_teamviewer_incoming_connection was storable nowhere and refused nothing
// (issue #832). Adding a fifth literal would have repeated the mistake.
//
// 255 rather than the 70 that would just fit today. These identifiers come from a corpus whose naming is not ours to control, so
// the width needs headroom a future import will not exhaust, and the load-time refusal is what catches anything past it. 255 is
// also already this schema's convention for a bounded external string (host_id), and it is the largest width that still keeps
// utf8mb4 columns on InnoDB's two-byte length prefix, which is what makes widening the existing tables an in-place operation
// rather than a table rebuild.
//
// It is a CHARACTER count, matching how VARCHAR(n) is declared, and the loader measures runes rather than bytes to agree with it.
// Those differ: 255 multibyte characters is up to 1020 bytes, so comparing len() against this would refuse an identifier the
// columns can store. Rule identifiers are ASCII snake_case by convention, but nothing enforces that, and a convention is not a
// reason to measure the wrong thing.
const MaxRuleIDLen = 255

// Severity levels aligned with industry standards (CrowdStrike, MITRE).
// Same constant set as detection/api.Severity*.
const (
	SeverityLow      = detectionapi.SeverityLow
	SeverityMedium   = detectionapi.SeverityMedium
	SeverityHigh     = detectionapi.SeverityHigh
	SeverityCritical = detectionapi.SeverityCritical
)

// Alert source constants re-exported from detection/api so catalog rules can stamp Finding.Source without importing detection/api
// directly. The doc comment on rules/api (see doc.go) makes the no-detection-import rule explicit; mirror constants here whenever a
// rule needs one. Same values, same types, no behavior drift.
const (
	AlertSourceDetection          = detectionapi.AlertSourceDetection
	AlertSourceApplicationControl = detectionapi.AlertSourceApplicationControl
)

// --- Catalog types -------------------------------------------------------------

// Rule is a detection that the engine evaluates against a batch of
// events. Concrete rules live in rules/internal/catalog/.
type Rule interface {
	ID() string
	// DisplayName returns the single canonical human-readable name for the detection (issue #519). It is the one string a rule names
	// itself with everywhere a human reads it: Doc().Title (docs + /api/rules + UI) and Finding.Title (the alert) both derive from it,
	// so the operator who triages an alert, reads the docs, and writes an exclusion sees the same name mapped to one stable ID(). Unlike
	// ID() (the snake_case machine identifier), this is prose, e.g. "Keychain credential dump". A rule with multiple trigger arms still
	// emits this one title; which arm fired lives in the finding's Description, not in a forked title (SIEM/Sigma catalog convention:
	// one rule, one name). The catalog guard test (TestAll_CanonicalDisplayName) asserts Doc().Title == DisplayName(); the
	// fixture-replay harness and each rule's positive-detection test assert that findings carry it.
	DisplayName() string
	// Techniques returns the MITRE ATT&CK technique IDs the rule maps to (e.g. []string{"T1059.002", "T1105"}). Used for Navigator export
	// + UI badging. Return an empty slice, not nil, for "no mapping".
	Techniques() []string
	// Doc returns the operator-facing documentation for the rule. Surfaces in /docs/detection-rules.md and the UI's per-rule detail page;
	// tools/gen-rule-docs reads it directly. Required (not optional) so a new rule cannot ship without a description and a severity
	// attestation: the compile error is the gate.
	Doc() Documentation
	// Platforms returns the operating systems the rule targets, one or more of the Platform* values. The engine evaluates the rule only
	// against events whose platform is in this set (ADR-0018), so a macOS-tradecraft rule never fires on a Windows event. Required (not
	// optional) so a new rule cannot ship without a platform attestation: the compile error is the gate, like Doc(). The catalog guard
	// test asserts every registered rule returns a non-empty set of valid platforms.
	Platforms() []Platform
	// Evaluate runs the rule against a batch of events. Implementations may use gr to walk the historical process graph but must not
	// mutate state. Returning nil findings is the common case.
	//
	// The two error classes are handled differently, and the difference matters to rule authors. An ordinary error discards this
	// rule's findings for the batch and is logged at WARN, isolating a misbehaving rule from the rest. An error wrapping
	// ErrProcessNotYetMaterialized does NOT discard them: the engine persists whatever findings came back alongside it and still
	// propagates the miss, so the processor retries the batch and alert dedup makes the re-run idempotent.
	//
	// An implementation MUST NOT abandon the rest of the batch when one event raises ErrProcessNotYetMaterialized. Finish evaluating
	// every event, then return the findings that DID resolve together with the miss: the engine persists those findings and still
	// retries the batch. Bailing on the first miss lets a permanently orphaned event (its fork/exec never captured, so its row never
	// arrives) mask a real finding elsewhere in the same batch until that finding's own grace window has elapsed, at which point it
	// degrades to the silent skip and is lost for good (issue #661). The catalog's pendingMiss helper implements this policy.
	Evaluate(ctx context.Context, events []Event, gr GraphReader) ([]Finding, error)
	// SupportedExclusionMatchTypes returns the exclusion match types this rule consults at evaluation time, i.e. the match types it
	// passes to the ExclusionResolver. It returns no match types (nil or an empty slice, treated alike) for a rule that consults no
	// exclusions. This is the single source of truth (issue #520) the create-exclusion API validates against and the admin UI's
	// match-type picker derives from, so a rule can never offer an exclusion dimension it silently ignores. The catalog guard test
	// asserts a rule never queries a match type outside this set.
	SupportedExclusionMatchTypes() []ExclusionMatchType
}

// NonDetectionKind names why a registered rule is not a detection. Used only as the return of NonDetection.
type NonDetectionKind string

const (
	// NonDetectionProjection is a registered rule that projects a decision the agent already made into the alert stream rather than
	// detecting anything. It carries no detection logic to inspect and makes no claim about adversary behaviour.
	NonDetectionProjection NonDetectionKind = "projection"
	// NonDetectionHealth is a registered rule whose subject is our own agent's operational state rather than activity on the host.
	// A person still needs to act on it, but it is a statement about the sensor, not about an adversary.
	NonDetectionHealth NonDetectionKind = "health"
)

// NonDetection is an OPTIONAL interface a registered rule implements to declare that it is not a detection. It is deliberately
// opt-in and absent from Rule: a detection is the overwhelmingly common case and must stay the zero-effort default, so a new rule
// that says nothing is treated as a detection. Only the rare rule that is something else has to say so, in its own file, next to
// the doc comment that explains why.
//
// The distinction is about the CATALOG SURFACE, not about evaluation. A non-detection is registered, evaluated and persisted
// exactly like any other rule; it is omitted from the operator-facing catalog (GET /api/rules, GET /api/attack-coverage, and the
// generated docs/detection-rules.md) because those surfaces describe detections an operator can read, tune and reason about.
// Publishing a rule there that has no detection logic, no tuning surface and no adversary claim misleads on all three counts, and
// in the ATT&CK case inflates a coverage figure that is read during procurement.
//
// Registered non-detections and why:
//
//   - application_control_block is a NonDetectionProjection. The blocking decision was made on the host by the AUTH_EXEC walker;
//     this rule renders it as an alert row. Its findings borrow the matched app-control rule's id and severity from the event
//     payload rather than carrying its own, which is why it is also the one rule exempt from the Finding.Title == DisplayName
//     invariant.
//   - sensor_recovery_failed is a NonDetectionHealth. It reports that our own automatic repair of a stopped capture provider gave
//     up, and both documented causes are faults in our software rather than adversary action.
type NonDetection interface {
	NonDetectionKind() NonDetectionKind
}

// AlgorithmNamer is an OPTIONAL interface a registered rule implements to name the evaluator that runs it. Optional and absent
// from Rule for the same reason NonDetection is: it is metadata about the implementation, not something the engine needs to
// evaluate anything, so requiring it would make every future rule carry a declaration the engine never reads.
//
// It exists for the exported rule file. A rule whose logic lives in Go rather than in a declarative detection block is still
// meant to be inspectable, and "which algorithm decides this" is the part an operator cannot otherwise learn without reading the
// source. The name is the same one the format reference uses (ancestor_walk_path_prefix, dns_resolve_then_connect, and so on).
//
// The -er suffix is deliberate: a single-method interface named for its method is the Go convention (Stringer, Reader), and it
// keeps this off the same lint that a bare Algorithm/Algorithm() pairing trips.
type AlgorithmNamer interface {
	AlgorithmName() string
}

// OriginNamer is an OPTIONAL interface a rule implements to say where it came from. A rule that does not implement it was written
// for this engine, which is the common case and is why the interface is optional rather than part of Rule: an authored rule
// should not have to declare the obvious. It still gets credited, because OriginOf supplies ProjectOrigin in its place.
type OriginNamer interface {
	Origin() string
}

// ProjectOrigin is the attribution carried by every rule this project wrote, i.e. every rule that declares no OriginNamer.
//
// It exists so attribution is TOTAL rather than conditional. The vendored corpus ships under the Detection Rule License, which
// requires crediting the author wherever a match is displayed, and the surface that has to satisfy that is the alert view. A
// surface that renders attribution only when it happens to be non-empty is one upstream rule away from displaying a match with no
// credit at all, and it also reads as though an uncredited rule came from nowhere. Giving our own rules a real value makes the
// presence of attribution invariant and moves the question a reader is actually asking ("whose rule is this?") onto the value.
const ProjectOrigin = "Fleet EDR"

// OriginOf returns r's declared origin, or ProjectOrigin for a rule this project authored.
//
// Never returns "": see ProjectOrigin. Callers may therefore render the result unconditionally, and a blank origin reaching a
// display surface means the value was dropped in transit rather than that the rule declined to name itself.
func OriginOf(r Rule) string {
	namer, ok := r.(OriginNamer)
	if !ok {
		return ProjectOrigin
	}
	// A rule that implements the interface but returns nothing is still credited: the interface says "I came from somewhere
	// else", so falling back to ProjectOrigin would credit US for someone else's work, which is the one wrong answer here.
	if origin := namer.Origin(); origin != "" {
		return origin
	}
	return UnknownOrigin
}

// UnknownOrigin is the attribution for a rule that declares an OriginNamer but names nothing. Distinct from ProjectOrigin because
// crediting ourselves for a rule that announced foreign provenance would be worse than admitting we cannot name the author.
const UnknownOrigin = "unknown upstream"

// AlertOriginOf returns the attribution to stamp on an alert r raises, which is NOT always r's own origin.
//
// A NonDetectionProjection renders a decision someone else already made, and its findings deliberately carry that other party's
// rule id rather than the projection's own: application_control_block copies the matched app-control policy's id off the event
// payload. Stamping this project's name onto such an alert would state that we authored an operator's blocklist entry, which is
// false, and there is no third party to credit in its place either. So a projection's alerts carry no attribution, and the
// display surfaces render nothing, which is the same thing they already do for an alert raised before attribution existed.
//
// Every other rule genuinely authors what it raises, health signals included: sensor_recovery_failed reports a failure in OUR
// software, so crediting this project for it is accurate. This is the same Projection-not-Health split the #519 title invariant
// makes, for the same underlying reason.
func AlertOriginOf(r Rule) string {
	if nd, ok := r.(NonDetection); ok && nd.NonDetectionKind() == NonDetectionProjection {
		return ""
	}
	return OriginOf(r)
}

// AlgorithmNameOf returns r's declared algorithm name, or "" when the rule declares none.
func AlgorithmNameOf(r Rule) string {
	namer, ok := r.(AlgorithmNamer)
	if !ok {
		return ""
	}
	return namer.AlgorithmName()
}

// IsDetection reports whether r is a detection, i.e. whether it belongs on the operator-facing catalog surfaces. A rule that does
// not implement NonDetection is a detection.
func IsDetection(r Rule) bool {
	_, nonDetection := r.(NonDetection)
	return !nonDetection
}

// ErrRetryBatch signals that a rule could not decide yet and the batch should be re-evaluated rather than acked. The engine treats
// an Evaluate error wrapping it as retryable, unlike ordinary rule failures (which are logged and swallowed): it fails the batch so
// the processor nacks it and re-evaluates. Alert dedup makes the re-run idempotent.
//
// It exists so "not decidable yet" is separable from WHY. The original reason was a subject process that had not materialized, and
// a rule that waits for something else (sensor_tamper waits out a recovery window, which has nothing to do with the process graph)
// must not be counted on the materialization-retry metric or logged as a materialization miss: that counter is how an operator
// detects a replica behind on graph materialization, and polluting it with unrelated waits destroys the signal (issue #631).
//
// A rule raising this MUST bound how long it will keep raising it, or a batch that can never be decided retries forever.
var ErrRetryBatch = errors.New("rules: batch not yet decidable")

// ErrProcessNotYetMaterialized signals that rule evaluation saw an event whose own (subject) process row has not been written by
// the graph builder yet. Since intra-replica processor concurrency (issue #535) two claim batches of the same host can be in flight
// at once, so an event can be evaluated before the concurrent batch carrying its fork/exec commits; the same window exists across
// replicas (ADR-0011). The engine treats an Evaluate error wrapping this sentinel as retryable, unlike ordinary rule failures
// (which are logged and swallowed): it fails the batch so the processor nacks it and re-evaluates once the row lands. Alert dedup
// makes the re-run idempotent. Rules raise it only while the event is younger than the materialization grace window, so an event
// whose process genuinely never materializes (e.g. a pre-capture pid) degrades to the historical silent skip instead of retrying
// forever.
// It wraps ErrRetryBatch, so a consumer asking "should this batch be retried" matches both, while a consumer reporting WHY (the
// materialization counter and its log line) still distinguishes this specific cause.
var ErrProcessNotYetMaterialized = fmt.Errorf("%w: subject process not yet materialized", ErrRetryBatch)

// RuleMetadata is the per-rule descriptor the operator endpoints render. Used in two surfaces: GET /api/rules (the operator handler
// maps the fields into a JSON-tagged ruleResponse struct, so the wire shape lives in rules/internal/operator and isn't on this
// struct) and GET /api/attack-coverage (the handler uses ID + Techniques fields directly to build the Navigator layer). The UI's
// RuleDetail.tsx and tools/gen-rule-docs both depend on the wire shape, so renaming a field here ripples through both.
type RuleMetadata struct {
	ID         string
	Techniques []string
	Doc        Documentation
	// SupportedExclusionMatchTypes mirrors the rule's SupportedExclusionMatchTypes() (issue #520). Surfaced on GET /api/rules so the
	// admin UI offers only the match types the rule consults, and validated against by the create-exclusion API.
	SupportedExclusionMatchTypes []ExclusionMatchType
	// Platforms mirrors the rule's Platforms() (ADR-0018). Surfaced on GET /api/rules so operators can see which operating systems a
	// rule applies to.
	Platforms []Platform
	// Algorithm mirrors the rule's AlgorithmName() when it declares one, and is empty otherwise. Names the evaluator that decides
	// the rule, which is what makes a Go-implemented rule inspectable without reading the source. Consumed by the rule-file export.
	Algorithm string
	// Origin names where the rule came from: ProjectOrigin for one this project authored, and the upstream project plus that
	// rule's own author for one it vendored. Never empty (see api.OriginOf), so a surface may render it unconditionally.
	// Surfaced so the operator-facing reference can credit third-party rules and so a reader can tell whose rule they are looking
	// at, which they otherwise cannot: a vendored rule is rendered exactly like an authored one.
	Origin string
	// DefaultMode mirrors the rule's DefaultMode() when it declares one (api.ModeDefaulter) and is DetectionRuleModeAlert otherwise,
	// so it is always a mode rather than sometimes empty. Surfaced on GET /api/rules because a detection that does not alert has to
	// be distinguishable from one that does without reading the source: the rule-settings surface lists only settings an operator
	// created, so a rule left at its own default appears nowhere on it.
	DefaultMode DetectionRuleMode
	// Mode is the mode the rule actually runs in at global scope: the globally scoped setting when one applies, DefaultMode
	// otherwise. This is the field that answers "what is this rule doing"; DefaultMode answers "what was it written to do".
	Mode DetectionRuleMode
	// ModeSource says which of the two produced Mode, and it is the ONLY thing that says so. Comparing Mode to DefaultMode does not:
	// an operator can set a rule to the mode it already declared, which is what putting a promoted rule back in monitor does, and
	// the two fields are then equal with the mode nonetheless chosen by a person. A reader needs the distinction because a rule
	// sitting in monitor because that is how it shipped is waiting to be reviewed, while one an operator moved there is a decision
	// already taken.
	ModeSource RuleModeSource
}

// Documentation is the structured per-rule descriptor consumed by the
// markdown generator, /api/rules, and the UI's rule detail page.
type Documentation struct {
	// Title is the operator-facing display name (e.g. "Keychain credential dump"). It MUST equal the rule's DisplayName() (issue #519):
	// it is set from r.DisplayName() in every Doc() so the docs, /api/rules, and the alert all show one canonical name. Distinct from
	// ID(): IDs are stable snake_case identifiers used in alert rows; the title is the human-readable label. The catalog guard test
	// enforces Title == DisplayName().
	Title string `json:"title"`
	// Summary is a one-sentence elevator pitch shown in lists / tooltips.
	Summary string `json:"summary"`
	// Description is the long-form behavioural spec (a few short
	// paragraphs). Plain text; renderers may turn newlines into paragraphs.
	Description string `json:"description"`
	// Severity is the SeverityLow|Medium|High|Critical constant the rule emits. Stored separately from per-finding severities because a
	// single rule always emits a single class today.
	Severity string `json:"severity"`
	// EventTypes lists the agent event types the rule consumes (e.g. "exec", "open"). Two audiences read it, and the second one
	// makes it a correctness contract rather than documentation.
	//
	// Operators read it to decide which ESF/NE subscriptions a minimal deployment must keep enabled.
	//
	// The detection engine DISPATCHES on it (issue #762): a rule is evaluated only for batches carrying at least one event of a
	// type listed here. So this list MUST cover every event type the rule can act on. Under-declaring does not fail, log, or
	// alert; the rule is simply never invoked for the batches it would have matched, and those findings are lost silently. Values
	// must be event types the agent actually emits, per the enum in schema/events.json.
	//
	// An empty list means "invoke for every batch". That is the fail-open direction, chosen because over-invoking costs time while
	// under-invoking costs detections, but a shipped rule relying on it forfeits dispatch and the catalog guard tests reject it.
	EventTypes []string `json:"event_types"`
	// FalsePositives names well-known legitimate sources that can trip the rule. Each entry is one short sentence; UI renders as a
	// bullet list.
	FalsePositives []string `json:"false_positives,omitempty"`
	// Limitations names known coverage gaps so an operator knows what the rule does NOT catch (atomic renames, env-inherited DYLD vars,
	// etc.).
	Limitations []string `json:"limitations,omitempty"`
	// References links the sources the rule was written from: an upstream rule's own `references` for a vendored rule, and the
	// research a hand-written one is based on. Together with Origin this is the provenance an operator needs to judge a detection
	// they did not write, which for the vendored corpus is most of them.
	//
	// Usually absolute URLs, but NOT guaranteed to be: these are copied verbatim from an upstream file that is free to cite a
	// DOI, a book, or a sentence. A consumer must not assume every entry is linkable, and must not render one as a link without
	// checking its scheme, since an upstream string is untrusted input and a non-http(s) scheme in an anchor is executable.
	References []string `json:"references,omitempty"`
}

// --- Application Control types -----------------------------------------------
//
// The application control subsystem replaces the legacy singleton
// blocklist. These types live on the public surface of rules/api so
// the server-side REST handlers, the agent command codec, and the
// extension snapshot loader can all reference one canonical shape
// without importing each other.

// DefaultPolicyName is the name of the policy seeded at bootstrap. Created empty; admins add rules to it via the REST surface.
// Multi-policy support is on the post-demo backlog; for the demo cut the deployment has exactly one policy with this name.
const DefaultPolicyName = "Default"

// DefaultHostGroupName is the name of the built-in "every enrolled host" host group seeded at bootstrap. The Default policy is
// assigned to this group by default, which is what makes the fan-out reach every enrolled host in Phase A. Editable host groups
// arrive in Phase B; Phase A only ever has this single row.
const DefaultHostGroupName = "all-hosts"

// HostGroupCriteriaTypeAll is the discriminator value the bootstrap writes into the built-in all-hosts group's `criteria` JSON
// document. The resolver in the fan-out path expands `{"type":"all"}` into every enrolled host. Phase B extends the discriminator
// with `"type":"tag"`, `"type":"hostname_pattern"`, etc., without a schema change because criteria is JSON.
const HostGroupCriteriaTypeAll = "all"

// RuleType is the wire-shape identifier of an application-control rule's matching dimension. The schema's `rule_type` ENUM mirrors
// this set, and the extension's ApplicationControlStore populates and matches a keyed index for every one of them, so all six are
// enforced. (An earlier revision of this comment said only BINARY was; that stopped being true once the CERTIFICATE / PATH and
// SIGNINGID / TEAMID deciders landed.)
type RuleType string

const (
	// RuleTypeCDHash matches against the signed Code Directory hash. 40 lowercase hex characters; only honored for hardened-runtime
	// processes per the spec.
	RuleTypeCDHash RuleType = "CDHASH"
	// RuleTypeBinary matches against the SHA-256 of the executable file. 64 lowercase hex characters.
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

// IsValidRuleType returns true for every defined RuleType value. Used at REST handler boundaries to validate untrusted query
// parameters before they reach the Store (which would otherwise silently produce an empty result set for unknown values
// instead of a typed 400). Mirrors the spec's enumerable RuleType set.
func IsValidRuleType(rt RuleType) bool {
	switch rt {
	case RuleTypeCDHash, RuleTypeBinary, RuleTypeSigningID, RuleTypeCertificate, RuleTypeTeamID, RuleTypePath:
		return true
	}
	return false
}

// Action is the verb a matched rule applies. The demo cut and the rest of Phase A constrain this to BLOCK; ALLOW and SILENT_BLOCK
// arrive with the Lockdown change. Stable wire-shape string; renaming is a contract break.
type Action string

const (
	ActionBlock Action = "BLOCK"
)

// Enforcement is the rule's audit-vs-enforce switch. The column is reserved in this phase: every rule runs as PROTECT. The DETECT
// semantic (log the would-be decision but allow the exec) arrives with the Lockdown change.
type Enforcement string

const (
	EnforcementProtect Enforcement = "PROTECT"
	EnforcementDetect  Enforcement = "DETECT"
)

// Severity classifies the alert that a triggered rule produces. Aligned with the existing alert severities (Severity* constants above)
// so a Sonar / Codecov / SIEM operator sees a unified scale across detection rules and application-control rules.
type Severity string

const (
	SeverityRuleLow      Severity = "low"
	SeverityRuleMedium   Severity = "medium"
	SeverityRuleHigh     Severity = "high"
	SeverityRuleCritical Severity = "critical"
)

// IsValidSeverity returns true for every defined Severity value. Used at REST handler boundaries to validate untrusted
// query parameters before they reach the Store.
func IsValidSeverity(s Severity) bool {
	switch s {
	case SeverityRuleLow, SeverityRuleMedium, SeverityRuleHigh, SeverityRuleCritical:
		return true
	}
	return false
}

// Source records where a rule came from. `admin` is the human-edited case the demo exercises; `imported` is a Santa StaticRules import
// (post-demo); `intel` is a threat-intel feed entry (post-demo).
type Source string

const (
	SourceAdmin    Source = "admin"
	SourceImported Source = "imported"
	SourceIntel    Source = "intel"
)

// PolicyDefaultAction is the policy-level fallback verdict when no rule matches. Constrained to NONE in this phase (default-allow);
// the Lockdown change extends the enum with BLOCK so admins can flip a policy to default-deny.
type PolicyDefaultAction string

const (
	PolicyDefaultActionNone PolicyDefaultAction = "NONE"
)

// FallbackPosture is the policy-level verdict the extension applies when AUTH_EXEC could not compute a BINARY rule SHA-256
// within the kernel deadline budget. Three options trade enforcement strictness against exec-startup latency and operator
// visibility; see extension/edr/extension/AuthExecDecider.swift FallbackPosture for the per-case rationale. v0.1.0 ships
// FallbackPostureFailClosed as the default for every snapshot; per-policy configurability arrives in the v0.1.x follow-up
// that adds a DB column and the REST surface to set it.
type FallbackPosture string

const (
	FallbackPostureFailClosed FallbackPosture = "fail-closed"
	FallbackPostureFailOpen   FallbackPosture = "fail-open"
	FallbackPostureAuditOnly  FallbackPosture = "audit-only"
)

// DefaultFallbackPosture is the value MarshalSetApplicationControlPayload substitutes when ApplicationControlPolicy carries
// an empty DeadlineFallback (the v0.1.0 norm because no DB column persists the field yet). Centralised so the wire default
// can move with the product without sweeping callers.
const DefaultFallbackPosture = FallbackPostureFailClosed

// IsValidFallbackPosture reports whether s names one of the documented enum values. Used by the REST validation surface that
// arrives with the v0.1.x configurability follow-up.
func IsValidFallbackPosture(s FallbackPosture) bool {
	switch s {
	case FallbackPostureFailClosed, FallbackPostureFailOpen, FallbackPostureAuditOnly:
		return true
	}
	return false
}

// ApplicationControlPolicy mirrors a row in app_control_policies. Used by the REST surface for list/get responses and by the fan-out
// code when constructing the `set_application_control` agent command. Rules is populated by GetWithRules and the rule listing
// endpoints; bare Get omits it. AssignmentCount is a derived field every policy fetch path populates (GetPolicyByName,
// GetPolicyByID, ListPolicies) so the UI's policies-list view can render "N host groups" without an N+1 round trip. Other
// internal callers (create/update audit paths) get a populated count they may ignore; the field is always authoritative.
// The seeded Default policy starts at 1 (its assignment to the seed all-hosts group); policies created via CreatePolicy start
// at 0 and grow when Phase B opens up assignment editing.
type ApplicationControlPolicy struct {
	ID            int64               `json:"id"`
	Name          string              `json:"name"`
	Description   string              `json:"description"`
	Version       int64               `json:"version"`
	DefaultAction PolicyDefaultAction `json:"default_action"`
	// DeadlineFallback is the per-policy posture the extension applies when AUTH_EXEC cannot compute a BINARY hash within the
	// kernel deadline budget. v0.1.0 has no DB column for this field; CreatePolicy/UpdatePolicy ignore it and the marshal
	// substitutes DefaultFallbackPosture (fail-closed) on empty values. The v0.1.x follow-up that adds DB persistence + a REST
	// surface to set the posture will start carrying real values through here.
	DeadlineFallback FallbackPosture          `json:"deadline_fallback,omitempty"`
	CreatedAt        time.Time                `json:"created_at"`
	UpdatedAt        time.Time                `json:"updated_at"`
	CreatedBy        string                   `json:"created_by"`
	UpdatedBy        string                   `json:"updated_by"`
	AssignmentCount  int                      `json:"assignment_count"`
	Rules            []ApplicationControlRule `json:"rules,omitempty"`
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

// CreateRuleRequest carries the operator-supplied fields for a new rule. The server fills in `Enabled=true`, `Action=BLOCK`,
// `Enforcement=PROTECT`, `Source=admin`, `CreatedBy=<session user>` and timestamps. Severity defaults to medium when blank.
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

// UpdateRuleRequest is the server-internal contract for PATCH /api/v1/app-control/rules/{id}. Every mutable field is a pointer so
// "field absent" (nil) is distinguishable from "field set to zero value". Phase A allows mutating Enabled, Severity, CustomMsg,
// CustomURL, Comment, and ExpiresAt. Phase B's Detect-mode change layers Enforcement on top; this struct does not carry it today.
// PolicyID is set by the handler from the existing row (PATCH does not move a rule between policies), Actor and Reason are required
// for every state-changing call so the audit row is honest.
type UpdateRuleRequest struct {
	RuleID    int64
	Enabled   *bool
	Severity  *Severity
	CustomMsg *string
	CustomURL *string
	Comment   *string
	ExpiresAt *time.Time
	Actor     string
	Reason    string
}

// DeleteRuleRequest is the server-internal contract for DELETE /api/v1/app-control/rules/{id}. Actor + Reason are required so the
// audit row records who removed the rule and why; the store-layer guard fails closed if either is empty.
type DeleteRuleRequest struct {
	RuleID int64
	Actor  string
	Reason string
}

// CreatePolicyRequest is the server-internal contract for POST /api/v1/app-control/policies. Name is required and must be unique;
// description is optional. Reason + Actor land on the audit row. The store hardcodes default_action='NONE' in Phase A (the column's
// enum only carries that value; Lockdown extends it).
type CreatePolicyRequest struct {
	Name        string
	Description string
	Actor       string
	Reason      string
}

// UpdatePolicyRequest is the server-internal contract for PATCH /api/v1/app-control/policies/{id}. Phase A only allows renaming and
// editing the description. Pointer fields distinguish "absent" from "explicit zero" so a PATCH that wants to clear the description
// (set it to "") sends `description: ""` rather than the field being omitted entirely.
type UpdatePolicyRequest struct {
	PolicyID    int64
	Name        *string
	Description *string
	Actor       string
	Reason      string
}

// DeletePolicyRequest is the server-internal contract for DELETE /api/v1/app-control/policies/{id}. The store-layer guard refuses
// to delete the seed Default policy by name (ErrAppControlPolicyImmutable) so the failsafe assignment stays intact.
type DeletePolicyRequest struct {
	PolicyID int64
	Actor    string
	Reason   string
}

// BulkUpsertRuleItem is one row in a BulkUpsertRulesRequest. Mirrors the wire shape POST /policies/{id}/rules:bulkUpsert
// consumes per element. Idempotency key is (policy_id, rule_type, identifier) per the openspec; severity / custom_msg /
// custom_url / comment overwrite the existing row when the key collides. PolicyID is supplied by the request envelope, not by
// each item, so the operator cannot accidentally mix policies inside one batch.
type BulkUpsertRuleItem struct {
	RuleType   RuleType
	Identifier string
	Severity   Severity
	CustomMsg  *string
	CustomURL  *string
	Comment    string
}

// BulkUpsertRulesRequest is the server-internal contract for POST /policies/{id}/rules:bulkUpsert. All-or-nothing semantics:
// any item that fails validation rejects the whole batch (the partial-commit alternative would leave the operator with a
// half-imported state that's hard to reconcile). Actor + Reason land on the single audit row that fires for the logical
// operation regardless of how many items the batch contained.
type BulkUpsertRulesRequest struct {
	PolicyID int64
	Items    []BulkUpsertRuleItem
	Actor    string
	Reason   string
}

// BulkUpsertResult is the wire shape returned to a successful bulk-upsert. Inserted + Updated are the per-row outcome counts
// classified by snapshotting the existing (policy_id, rule_type, identifier) keys inside the same SELECT ... FOR UPDATE that
// serialises the batch: items whose key was already present count as Updated, the rest as Inserted. Rules is the full
// post-upsert row set in the order the request supplied so a UI can render the final state without an extra round trip.
type BulkUpsertResult struct {
	Inserted int                      `json:"inserted"`
	Updated  int                      `json:"updated"`
	Rules    []ApplicationControlRule `json:"rules"`
}

// MaxBulkUpsertItems caps a single bulk-upsert batch. The handler's 256 KiB body limit imposes a practical byte ceiling, but we
// also gate on item count so a 1000-row paste that happens to fit under the byte cap doesn't tie up the txn for minutes. 500
// matches the Phase A demo deployment's expected import size with headroom; Phase B can grow this when paste-many lands.
const MaxBulkUpsertItems = 500

// Application Control validation errors. Mapped to HTTP 400 by the
// REST handlers via IsApplicationControlValidationError.
var (
	// ErrAppControlPolicyNotFound is returned when the named policy
	// row does not exist.
	ErrAppControlPolicyNotFound = errors.New("rules: application control policy not found")

	// ErrAppControlInvalidRuleType is returned when the rule_type is not one of the documented enum values. Distinct from
	// ErrAppControlUnsupportedRuleType (which is the demo-cut signal that the type is on the enum but not yet wired through validation and
	// decisioning).
	ErrAppControlInvalidRuleType = errors.New("rules: invalid application control rule type")

	// ErrAppControlUnsupportedRuleType is returned when the rule_type is on the enum but the demo cut hasn't wired its validator and
	// decision-engine branch yet. Lifts as the remaining types come online; the constant stays as the named error so callers can errors.Is
	// on it without breaking when the message changes.
	ErrAppControlUnsupportedRuleType = errors.New("rules: rule type not yet supported")

	// ErrAppControlInvalidIdentifier is returned when the identifier does not match the format required by its rule_type (e.g. a BINARY
	// identifier that isn't 64 lowercase hex characters).
	ErrAppControlInvalidIdentifier = errors.New("rules: invalid application control rule identifier")

	// ErrAppControlInvalidSeverity is returned when the severity is
	// not one of low/medium/high/critical.
	ErrAppControlInvalidSeverity = errors.New("rules: invalid application control rule severity")

	// ErrAppControlInvalidRequest is returned when a request is missing required fields (e.g. empty actor or reason on a state-changing
	// call). Distinct from the identifier-shape errors above so audit logs can tell them apart.
	ErrAppControlInvalidRequest = errors.New("rules: invalid application control request")

	// ErrAppControlDuplicateRule is returned when a rule with the same (policy_id, rule_type, identifier) already exists. Mapped to HTTP
	// 409 by the REST handlers so the client can dedup idempotent retries cleanly.
	ErrAppControlDuplicateRule = errors.New("rules: application control rule already exists")

	// ErrAppControlRuleNotFound is returned when the targeted rule row does not exist. Mapped to HTTP 404 by the REST handler so the
	// REST client can distinguish "PATCH/DELETE on a stale id" from a server-side fault.
	ErrAppControlRuleNotFound = errors.New("rules: application control rule not found")

	// ErrAppControlDuplicatePolicy is returned when a policy with the same name already exists. Mapped to HTTP 409 by the POST policy
	// handler so an operator typing a name collision sees a precise diagnostic rather than a generic 500.
	ErrAppControlDuplicatePolicy = errors.New("rules: application control policy already exists")

	// ErrAppControlPolicyImmutable is returned when a destructive mutation targets the seed Default policy (DELETE policy). The seed
	// row is the failsafe that keeps the all-hosts assignment alive; an admin who wants to stop enforcing rules detaches the
	// assignment or disables individual rules rather than deleting the policy itself.
	ErrAppControlPolicyImmutable = errors.New("rules: application control default policy cannot be deleted")

	// ErrAppControlHostGroupNotFound is returned when the targeted host_group row does not exist. Mapped to HTTP 404 by the REST
	// handler so an operator hitting a stale id sees a typed signal rather than a generic 500.
	ErrAppControlHostGroupNotFound = errors.New("rules: application control host group not found")
)

// IsApplicationControlValidationError reports whether err is one of the validation errors that the REST handlers map to HTTP 400. The
// duplicate-rule and not-found errors are NOT in this set because they map to different HTTP codes; callers handle those explicitly.
func IsApplicationControlValidationError(err error) bool {
	return errors.Is(err, ErrAppControlInvalidRuleType) ||
		errors.Is(err, ErrAppControlUnsupportedRuleType) ||
		errors.Is(err, ErrAppControlInvalidIdentifier) ||
		errors.Is(err, ErrAppControlInvalidSeverity) ||
		errors.Is(err, ErrAppControlInvalidRequest)
}

// HostGroup mirrors a row in host_groups. Phase A has exactly one row (the built-in `all-hosts` group); editable groups arrive in
// Phase B. Criteria is a JSON document the fan-out resolver interprets: `{"type":"all"}` matches every enrolled host today; Phase B
// adds tag / hostname-pattern / OS predicates without a schema change.
type HostGroup struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Criteria    json.RawMessage `json:"criteria"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Assignment mirrors a row in app_control_assignments. Phase A has exactly one row (the seed `Default` → `all-hosts` link). Phase B
// uses Priority for conflict resolution when overlapping groups are assigned to different policies; Phase A leaves it at 0.
type Assignment struct {
	PolicyID    int64     `json:"policy_id"`
	HostGroupID int64     `json:"host_group_id"`
	Priority    int       `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
}

// ApplicationControlStore is the read+write surface the rules-context REST handler (and tests) consume. The concrete implementation
// lives at server/rules/internal/appcontrol; this interface lets callers outside the rules tree depend on the contract without pulling
// in the internal package (ADR-0004's bounded-context import rule).
type ApplicationControlStore interface {
	GetPolicyByName(ctx context.Context, name string) (ApplicationControlPolicy, error)
	// GetPolicyByID loads the policy row by primary key. Used by the service-layer snapshot composer and the policy-delete audit
	// path; replaces the prior practice of walking ListPolicies in memory to locate a single row by id.
	GetPolicyByID(ctx context.Context, policyID int64) (ApplicationControlPolicy, error)
	ListPolicies(ctx context.Context) ([]ApplicationControlPolicy, error)
	ListRulesByPolicy(ctx context.Context, policyID int64) ([]ApplicationControlRule, error)
	CreateRule(ctx context.Context, req CreateRuleRequest) (ApplicationControlRule, error)
	// GetRuleByID returns the rule row (or ErrAppControlRuleNotFound). The REST PATCH/DELETE paths use it to look up the policy_id
	// the row belongs to before mutating, so the snapshot fan-out targets the right policy.
	GetRuleByID(ctx context.Context, ruleID int64) (ApplicationControlRule, error)
	// UpdateRule applies a partial update to an existing rule + bumps the parent policy's version. Returns the post-update row.
	// ErrAppControlRuleNotFound when the rule does not exist; ErrAppControlInvalidRequest when actor/reason are empty.
	UpdateRule(ctx context.Context, req UpdateRuleRequest) (ApplicationControlRule, error)
	// DeleteRule removes the rule + bumps the parent policy's version. Returns the parent policy_id so the service can compose the
	// post-delete snapshot the agents see. ErrAppControlRuleNotFound when the rule does not exist.
	DeleteRule(ctx context.Context, req DeleteRuleRequest) (policyID int64, err error)
	// CreatePolicy inserts a new policy row. ErrAppControlDuplicatePolicy when the name collides.
	CreatePolicy(ctx context.Context, req CreatePolicyRequest) (ApplicationControlPolicy, error)
	// UpdatePolicy applies a partial update (name / description) + bumps the policy version + sets updated_by. Returns the post-update
	// row. ErrAppControlPolicyNotFound when the id does not exist; ErrAppControlDuplicatePolicy when the new name collides.
	UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (ApplicationControlPolicy, error)
	// DeletePolicy removes the policy row (CASCADEs rules + assignments). Refuses the seed Default policy via
	// ErrAppControlPolicyImmutable. ErrAppControlPolicyNotFound when the id does not exist.
	DeletePolicy(ctx context.Context, req DeletePolicyRequest) error
	// BulkUpsertRules applies an idempotent upsert across the request's items, bumps the parent policy version once, and
	// returns the post-upsert rows + insert/update counts. All-or-nothing: any item failing validation rejects the whole
	// batch. ErrAppControlPolicyNotFound when policy_id is missing; the per-item validator errors propagate untouched so the
	// REST handler can errors.Is on the shared IsApplicationControlValidationError set.
	BulkUpsertRules(ctx context.Context, req BulkUpsertRulesRequest) (BulkUpsertResult, error)
	// ListHostGroupsForPolicy returns the host groups assigned to the policy, in priority order then by group name. The fan-out
	// resolver walks the result and unions the member hosts of each group to build the set of unique hosts the rule update should
	// reach.
	ListHostGroupsForPolicy(ctx context.Context, policyID int64) ([]HostGroup, error)
	// ListHostGroups returns every host_group row in alphabetical name order. Phase A always returns the single seed `all-hosts`
	// group; Phase B grows the result when editable groups land. Pure read; no fan-out, no audit.
	ListHostGroups(ctx context.Context) ([]HostGroup, error)
	// GetHostGroupByID loads one host_group row. ErrAppControlHostGroupNotFound when the row does not exist; the REST handler
	// maps that to HTTP 404.
	GetHostGroupByID(ctx context.Context, hostGroupID int64) (HostGroup, error)
	// ListAssignmentsForPolicy returns the raw assignment rows (policy_id, host_group_id, priority, created_at) for the policy
	// in (priority ASC, host_group_id ASC) order. Distinct from ListHostGroupsForPolicy: this returns the join-table rows
	// themselves so a future UI can render the priority + linkage independent of the group metadata.
	ListAssignmentsForPolicy(ctx context.Context, policyID int64) ([]Assignment, error)
	// ListRulesAcrossPolicies returns rules matching the filter across every policy. Powers the cross-policy GET /rules endpoint
	// that integration callers (audit export, compliance reports) need. Pagination is mandatory: Limit caps the page size and
	// Offset cursors through the result. Returns the page rows + the total count so the caller can render "Showing N of M".
	ListRulesAcrossPolicies(ctx context.Context, req ListRulesAcrossPoliciesRequest) (ListRulesAcrossPoliciesResult, error)
}

// ListRulesAcrossPoliciesRequest is the filter envelope for the cross-policy rules list. Every field is optional except Limit;
// the empty / nil / zero value for any dimension means "no constraint on this dimension" (logical AND across set dimensions).
// PolicyID acts as a single-policy filter (=== ListRulesByPolicy when set); the cross-policy use case leaves it nil.
type ListRulesAcrossPoliciesRequest struct {
	PolicyID *int64   // nil = every policy
	RuleType RuleType // empty = any type
	Enabled  *bool    // nil = any state
	Severity Severity // empty = any severity
	Source   string   // empty = any source
	Limit    int      // 1..MaxListRulesAcrossPoliciesLimit; 0 falls through to DefaultListRulesAcrossPoliciesLimit at the handler boundary
	Offset   int      // 0-based; combine with Limit for pagination
}

// ListRulesAcrossPoliciesResult is the page returned by ListRulesAcrossPolicies. Rules is the page rows in (policy_id, rule_type,
// identifier) order so pagination is deterministic. Total is the unfiltered-by-page count (matching the filter, ignoring
// Limit + Offset) so callers can render a "Showing N of M" counter without a second round trip.
type ListRulesAcrossPoliciesResult struct {
	Rules []ApplicationControlRule `json:"rules"`
	Total int                      `json:"total"`
}

// DefaultListRulesAcrossPoliciesLimit + MaxListRulesAcrossPoliciesLimit pin the pagination contract. The default trades against
// "operator scrolling through a few hundred rules" being one round trip vs. the page-size taking forever to render; the max
// caps the JSON-payload size at roughly 200 KiB at 400 bytes per rule.
const (
	DefaultListRulesAcrossPoliciesLimit = 100
	MaxListRulesAcrossPoliciesLimit     = 500
)

// CommandTypeSetApplicationControl is the well-known command type the agent reads on every poll and routes to its application-control
// snapshot dispatcher. Stable wire-shape string; renaming is a contract break for every deployed agent.
const CommandTypeSetApplicationControl = "set_application_control"

// SetApplicationControlPayload is the wire shape the server writes
// into a `set_application_control` command and the agent + extension
// decode end-to-end. Field tags are load-bearing: the extension
// (Swift) Decodable derives the JSON keys from these tags. A change
// here MUST land in lockstep with the matching change in
// ApplicationControlStore.swift.
//
// Lives in api/ so cmd/main and the REST handler can construct it
// without importing rules internals; the agent commander decodes the
// same shape with its own private struct to avoid pulling
// server/rules/api into the agent module graph.
type SetApplicationControlPayload struct {
	PolicyID      int64 `json:"policy_id"`
	PolicyVersion int64 `json:"policy_version"`
	// PolicyEpoch is the policy's server-assigned updated_at in Unix microseconds (0 when the policy carries no timestamp). It is the
	// restore-surviving companion to PolicyVersion: the extension accepts a snapshot when EITHER axis advances, so a server DB
	// restore that regresses PolicyVersion still re-syncs hosts because the operator's next mutation stamps a fresh updated_at that
	// is strictly greater than any pre-restore epoch (wall-clock only moves forward). A pre-fix server leaves this 0 on every push,
	// which the extension treats as "epoch never advances", falling back to the historical version-only gate. See #322.
	PolicyEpoch int64 `json:"policy_epoch"`
	// DeadlineFallback governs the extension's verdict when AUTH_EXEC cannot compute a BINARY rule SHA-256 within the kernel
	// deadline budget. Always populated by MarshalSetApplicationControlPayload (DefaultFallbackPosture when the upstream policy
	// did not set one) so the extension's snapshot never has to fall back to its own internal default. Pre-v0.1.0 agents that
	// decode this payload without the field present continue to substitute their own internal fail-closed default.
	DeadlineFallback FallbackPosture             `json:"deadline_fallback"`
	Rules            []SetApplicationControlRule `json:"rules"`
}

// SetApplicationControlRule is one row in the payload's rules array.
// Every field that the extension's decision walker (Step 3), block
// notification (Step 4), or block event (Step 4) needs lands here so
// the wire shape is stable across the demo cut and the rest of
// Phase A. Disabled and expired rules are NOT included in the
// payload: the fan-out filters them so the agent never sees them.
//
// RuleID is the stable string identifier (e.g. "app_control:42") that
// the extension echoes back in the `application_control_block` event
// so the server-side mapping lands the alert under the same rule_id.
// Built by ApplicationControlRuleID(r.ID); the numeric row id alone
// would risk collision with catalog rule ids in alert dedup.
type SetApplicationControlRule struct {
	RuleID      string      `json:"rule_id"`
	RuleType    RuleType    `json:"rule_type"`
	Identifier  string      `json:"identifier"`
	Action      Action      `json:"action"`
	Enforcement Enforcement `json:"enforcement"`
	Severity    Severity    `json:"severity"`
	CustomMsg   *string     `json:"custom_msg,omitempty"`
	CustomURL   *string     `json:"custom_url,omitempty"`
}

// ApplicationControlRuleIDPrefix namespaces the rule_id that the extension echoes in `application_control_block` events. Keeps the
// alert dedup key collision-free against catalog rule ids even when the alerts.source column is unavailable for filtering.
const ApplicationControlRuleIDPrefix = "app_control:"

// ApplicationControlRuleID renders the stable string rule_id for a row in app_control_rules. The extension treats this value as
// opaque; the server uses it for alert dedup and for mapping a block-event back to its row.
func ApplicationControlRuleID(id int64) string {
	return fmt.Sprintf("%s%d", ApplicationControlRuleIDPrefix, id)
}

// MarshalSetApplicationControlPayload returns the JSON bytes the agent's commander forwards to the extension. Filters disabled rules
// and rules whose expires_at is in the past so the agent + extension never see them. now is provided by the caller (cmd/main passes
// time.Now()) so tests can pin a deterministic clock; passing the zero value disables the expires_at filter (treat every rule as
// non-expired).
func MarshalSetApplicationControlPayload(p ApplicationControlPolicy, rules []ApplicationControlRule, now time.Time) (json.RawMessage, error) {
	entries := make([]SetApplicationControlRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if !now.IsZero() && r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		entries = append(entries, SetApplicationControlRule{
			RuleID:      ApplicationControlRuleID(r.ID),
			RuleType:    r.RuleType,
			Identifier:  r.Identifier,
			Action:      r.Action,
			Enforcement: r.Enforcement,
			Severity:    r.Severity,
			CustomMsg:   r.CustomMsg,
			CustomURL:   r.CustomURL,
		})
	}
	// Normalise both the empty zero-value (the v0.1.0 norm: no DB column persists the field yet, so every fetched policy
	// arrives with DeadlineFallback="") AND any non-empty but unrecognised value to DefaultFallbackPosture. The second branch
	// is the defensive one: a stray bad value sneaking into the policy struct (typo on a future REST surface, copy-paste from
	// an external feed, schema drift on the v0.1.x DB migration) must not reach the extension snapshot as a literal it cannot
	// decode: the extension's FallbackPosture enum is strict, and a snapshot decode failure deactivates Application Control
	// until the next valid push.
	posture := p.DeadlineFallback
	if !IsValidFallbackPosture(posture) {
		posture = DefaultFallbackPosture
	}
	// policy_epoch is the policy's updated_at in Unix microseconds. A zero UpdatedAt (the v0.1.0 norm in unit tests, and any
	// caller that hasn't populated the field) marshals to 0 rather than UnixMicro()'s large negative value for the zero time, so
	// the wire keeps a clean "unknown epoch" sentinel the extension reads as "never advances".
	var epoch int64
	if !p.UpdatedAt.IsZero() {
		epoch = p.UpdatedAt.UnixMicro()
	}
	return json.Marshal(SetApplicationControlPayload{
		PolicyID:         p.ID,
		PolicyVersion:    p.Version,
		PolicyEpoch:      epoch,
		DeadlineFallback: posture,
		Rules:            entries,
	})
}
