package api

import (
	"context"
	"time"
)

// AuditAction is a stable wire-shape identifier for an operator action
// the audit trail records. Values are namespaced as `<resource>.<verb>`
// and never repurposed once they ship in a release: downstream tooling
// (SIEM exporters, retention rules, alert dashboards) will match on the
// literal string, so a rename today is a contract break tomorrow. Add
// new actions; do not edit existing ones.
type AuditAction string

const (
	// AuditAuthLoginSuccess records a successful login. user_id and
	// actor_email are both populated from the authenticated user.
	AuditAuthLoginSuccess AuditAction = "auth.login.success"
	// AuditAuthLoginFailed records a failed login attempt. user_id is
	// nil (the email may be unknown or the password mismatched, both
	// produce the same wire 401, but the audit row records the
	// distinction in the reason field of the payload). actor_email
	// captures the attempted email so a brute force across many emails
	// shows up as a sequence in retention.
	AuditAuthLoginFailed AuditAction = "auth.login.failed"
	// AuditAuthLogout records a successful logout. user_id is the user
	// whose session was just invalidated.
	AuditAuthLogout AuditAction = "auth.logout"

	// Alert lifecycle (detection context). Constants are per-status
	// rather than per-verb because the wire shape PUT /api/alerts/{id}
	// takes the new status as a string ("acknowledged"/"resolved"/
	// "open") and the audit row mirrors that vocabulary so SIEM filters
	// stay aligned with the API. AlertReopen records a status flip back
	// to open, which is rare but auditable as a deliberate operator
	// action (reverting an over-eager triage decision).
	AuditAlertAcknowledge AuditAction = "alert.acknowledge"
	AuditAlertResolve     AuditAction = "alert.resolve"
	AuditAlertReopen      AuditAction = "alert.reopen"

	// Command issuance (response context).
	AuditCommandIssue AuditAction = "command.issue"

	// Enrollment lifecycle (endpoint context). Constants follow the
	// <resource>.<verb> convention documented at the top of this file:
	// rotate_token reads as "rotate the host token of the enrollment,"
	// matching the wire-shape command_type the agent dispatches on.
	AuditEnrollmentRevoke      AuditAction = "enrollment.revoke"
	AuditEnrollmentRotateToken AuditAction = "enrollment.rotate_token"

	// Break-glass flow (Phase 4b). Action names match the spec
	// scenario language verbatim: dashboards filter on the literal
	// strings, so any rename is a contract break. The flow is
	// distinct from auth.login.* because the recovery path needs a
	// dedicated row category for retention + alerting (a successful
	// break-glass login is rare and inherently noteworthy).
	AuditAuthBreakglassBootstrap AuditAction = "auth.breakglass.bootstrap"
	AuditAuthBreakglassSuccess   AuditAction = "auth.breakglass.success"
	AuditAuthBreakglassFailure   AuditAction = "auth.breakglass.failure"
)

// AuditEvent is the value passed to AuditRecorder.Record. Caller
// fills the application-layer fields; the Recorder pulls trace_id
// from ctx (which equals the X-Request-ID echoed in response headers)
// so handler code does not have to re-extract it. RemoteAddr is on
// the event because it derives from *http.Request, which is not on
// ctx by convention. occurred_at is set by the Recorder at INSERT
// time.
//
// TraceID is the explicit override path: when set, Recorder uses it
// instead of probing ctx. The async chokepoint emission populates
// TraceID at Submit time so the eventual INSERT (which runs under a
// background ctx without the original span) still attributes the row
// to the request that triggered it.
type AuditEvent struct {
	// UserID is the authenticated user, when one exists. Nil for
	// pre-auth events (login_failed) so the audit row records "who
	// attempted" without claiming "who was authenticated."
	UserID *int64
	// ActorEmail is the email that should be recorded on the row. For
	// successful actions the user.email at the time of action. For
	// login_failed, the attempted email even if no user exists.
	ActorEmail string
	Action     AuditAction
	// TargetType + TargetID identify the object the action applied to.
	// For unary actions (login, logout) leave both empty.
	TargetType string
	TargetID   string
	// TraceID is the OTel- / X-Request-ID trace id to record. Optional:
	// when empty, Recorder falls back to extracting it from the call's
	// ctx (the wave-1 sync default). Set explicitly by the chokepoint
	// before Submit so the async writer's background-ctx INSERT keeps
	// trace correlation. Lower-case 32-char hex per the existing
	// sync-path extractor.
	TraceID string
	// RemoteAddr is the peer address for retention/correlation. Today
	// this is r.RemoteAddr verbatim (not X-Forwarded-For); see #81 for
	// the trusted-proxy follow-up.
	RemoteAddr string
	// Payload is opaque per-action context (previous alert state, policy
	// diff, login_failed reason). Stored as MySQL JSON; the audit table
	// makes no schema commitment so individual handlers can record what
	// reviewers will need without a migration.
	Payload map[string]any
}

// AuditRecorder is the write side of the audit trail. The
// implementation is append-only by design: there is no Update or
// Delete method, and the table grants the application's DB user only
// SELECT and INSERT privileges in environments where DBA-level grant
// management is possible. Even where grants are uniform, the
// interface shape forces every audit-modifying code path to add a
// method (a code review signal) rather than slip a tampering UPDATE
// past unnoticed.
//
// Record blocks until the row is durably written. Synchronous on
// purpose: an audit row that's "in flight" at the moment of a process
// crash is not a useful audit trail. Throughput cost is modest (one
// INSERT per operator action), and operator-action volume is several
// orders of magnitude smaller than event ingest, so synchronous is
// the right default.
//
// Phase 3 carves out an async path for chokepoint emissions on
// read-action allow events; see AsyncAuditWriter and IsReadAction
// below. Sync remains the default for everything else (denies, writes,
// auth outcomes, break-glass) so the durability invariant stays
// intact on the events reviewers actually need post-incident.
type AuditRecorder interface {
	Record(ctx context.Context, e AuditEvent) error
}

// AsyncAuditWriter is the optional non-blocking sibling of
// AuditRecorder. The chokepoint routes high-volume read-allow audit
// events through Submit so the hot path of every privileged read does
// not wait on an INSERT. Submit is non-blocking: it returns true when
// the event was queued, false when the bounded buffer was full and
// the implementation logged a slog WARN as the dual-emit fallback.
//
// Submit must be safe to call concurrently from multiple goroutines.
//
// ctx contract: ctx is valid only for the synchronous part of Submit
// (the channel send + a slog.WarnContext on overflow). Implementations
// MUST NOT retain it for the eventual asynchronous DB write — the
// request-scoped ctx is cancelled the moment the handler returns,
// and an INSERT under a cancelled ctx silently drops the row. Per the
// AuditEvent doc: copy the trace_id (and any other ctx-derived fields)
// onto AuditEvent.TraceID before Submit; the writer's Run loop owns
// the lifecycle ctx for the actual INSERT.
//
// Lifecycle: implementations own a goroutine; cmd/main starts it via
// the per-context Run loop and stops it on ctx cancel. Pending
// events at shutdown flush with a per-row deadline before the loop
// returns; the slog backend captures anything still queued past the
// deadline.
type AsyncAuditWriter interface {
	Submit(ctx context.Context, e AuditEvent) bool
}

// IsReadAction reports whether action is one of the wave-1 read
// actions. The chokepoint uses it to gate the sampling + async path:
// only read-action allow events are eligible for sampling. Denies,
// writes, and auth outcomes always audit synchronously.
//
// ActionAuditRead is included in the read set semantically (it is a
// read of audit history) but the chokepoint exempts it from sampling
// — auditors need a record of who read the audit log, regardless of
// the operator's read_sampling configuration.
//
// The default branch returns false for every non-read action; adding
// a new read action to the Action enum requires adding it here too.
//
//nolint:exhaustive
func IsReadAction(a Action) bool {
	switch a {
	case ActionHostRead, ActionProcessRead,
		ActionAlertRead,
		ActionEnrollmentRead,
		ActionUserRead,
		ActionAuditRead:
		return true
	default:
		return false
	}
}

// AuditFilter constrains AuditReader.List. All fields are optional;
// zero-value means "no constraint on this dimension." Pagination uses
// (Limit, BeforeID) cursor: callers pass the smallest id from the
// previous page to walk back through history, since occurred_at + id
// is monotonic for any single MySQL writer (auto_increment id is
// strictly increasing within an instance).
type AuditFilter struct {
	UserID     *int64
	Action     AuditAction
	TargetType string
	TargetID   string
	Since      time.Time
	Until      time.Time
	Limit      int
	BeforeID   int64
}

// AuditReader is the read side. Separated from Recorder so that a
// future split (writer in the operator API, reader behind a separate
// admin-only mux) does not require touching the audit-emitting
// handlers.
type AuditReader interface {
	List(ctx context.Context, f AuditFilter) ([]AuditRow, error)
}

// AuditRow is the read-side shape returned by AuditReader. user_email
// is denormalised on read (LEFT JOIN against users) so the retrieval
// endpoint produces actionable rows in a single query, even after a
// user has been deleted from the users table (UserID then resolves to
// a nil-or-empty email).
type AuditRow struct {
	ID         int64          `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	UserID     *int64         `json:"user_id,omitempty"`
	UserEmail  string         `json:"user_email,omitempty"`
	Action     AuditAction    `json:"action"`
	TargetType string         `json:"target_type,omitempty"`
	TargetID   string         `json:"target_id,omitempty"`
	TraceID    string         `json:"trace_id,omitempty"`
	RemoteAddr string         `json:"remote_addr,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
}
