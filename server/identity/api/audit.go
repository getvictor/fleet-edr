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

	// Policy CRUD (rules context).
	AuditPolicyCreate AuditAction = "policy.create"
	AuditPolicyUpdate AuditAction = "policy.update"
	AuditPolicyDelete AuditAction = "policy.delete"

	// Command issuance (response context).
	AuditCommandIssue AuditAction = "command.issue"

	// Enrollment lifecycle (endpoint context).
	AuditEnrollmentRevoke       AuditAction = "enrollment.revoke"
	AuditEnrollmentTokenRotated AuditAction = "enrollment.token_rotated"
)

// AuditEvent is the value passed to AuditRecorder.Record. Caller fills
// the application-layer fields; the Recorder pulls trace_id from ctx
// (which equals the X-Request-ID echoed in response headers) so handler
// code does not have to re-extract it. RemoteAddr is on the event
// because it derives from *http.Request, which is not on ctx by
// convention. occurred_at is set by the Recorder at INSERT time.
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
type AuditRecorder interface {
	Record(ctx context.Context, e AuditEvent) error
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
