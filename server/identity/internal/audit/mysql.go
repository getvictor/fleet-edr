// Package audit owns the operator-action audit trail: the AuditRecorder
// implementation that handlers across every bounded context call when
// an operator action commits, and the read-side AuditReader the
// retrieval endpoint serves.
//
// Append-only is enforced by the interface shape (no Update / Delete
// methods on either Recorder or Reader) and reinforced at the SQL
// boundary by the absence of any non-INSERT write paths in this
// package. A future deployment that runs the application under a DB
// user with only SELECT + INSERT privileges on audit_events would be
// a configuration change rather than a refactor.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/identity/api"
)

// auditMeterName is the OTel instrumentation-scope name for the audit-recorder's metric. Stable string so a dashboard alert keyed on
// instrumentation.scope.name matches across versions.
const auditMeterName = "github.com/fleetdm/edr/server/identity/audit"

// Store implements both api.AuditRecorder and api.AuditReader against
// MySQL. Constructed once at boot from bootstrap.New and shared across
// every audit-emitting handler in the process.
//
// On every successful INSERT, Store dual-emits the row to slog at INFO
// with the same attribute shape the async writer uses on drops. The
// log line is the OTel-side mirror of the MySQL row; SigNoz dashboards
// chart auth + authz signal off these log entries (chokepoint denies
// surface as `action=authz.*` with `payload.decision=deny`, OIDC and
// break-glass outcomes surface as `action=auth.oidc.*` /
// `action=auth.breakglass.*`). MySQL remains the canonical store; the
// log emission is best-effort and runs after the row is durably
// committed, so a slog handler outage does not affect persistence.
type Store struct {
	db            *sqlx.DB
	logger        *slog.Logger
	writeFailures metric.Int64Counter
}

// New returns a Store. Panics if db is nil because a Store with a nil db is a programming error that would only surface at request
// time. A nil logger falls through to slog.Default(), matching AsyncWriter's shape so test code and lightweight wiring stays terse.
// The audit-write-failure counter is registered against the global meter so a Recorder injection is not required; when OTel is not
// wired (no OTEL_EXPORTER_OTLP_ENDPOINT) the counter is a no-op.
func New(db *sqlx.DB, logger *slog.Logger) *Store {
	if db == nil {
		panic("audit.New: db must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	counter, _ := otel.Meter(auditMeterName).Int64Counter(
		"edr.audit.write_failures",
		metric.WithDescription("Audit row INSERT failures into the audit_events table. Each increment is one row that the slog dual-emit captured but the DB rejected; the audit's append-only contract is broken."),
		metric.WithUnit("{failure}"),
	)
	return &Store{db: db, logger: logger, writeFailures: counter}
}

// Record inserts one audit row. trace_id is pulled from ctx so handler
// code does not have to thread it explicitly; if no span is active the
// column is left NULL (the row still records the action). occurred_at
// is set by the DB DEFAULT, so a clock skew between app and DB host
// shows up consistently across rows.
//
// When UserID is set but ActorEmail is empty (the common case for
// cross-context handlers that only see user_id on ctx, e.g. alert
// status changes), Record looks up the current email from users and
// denormalises it onto the audit row. That lookup is what keeps an
// audit row attributable after a user is later deleted: the LEFT JOIN
// on read returns "" for a missing user, but the denormalised
// actor_email column survives. A failed lookup leaves actor_email
// empty rather than failing the audit; the row still records the
// user_id, and reviewers can correlate via that.
//
// Synchronous: returns once the row is durably committed. The caller
// is expected to record audit AFTER the underlying action commits, so
// a successful audit row is evidence that the action persisted.
func (s *Store) Record(ctx context.Context, e api.AuditEvent) error {
	if e.Action == "" {
		return errors.New("audit.Record: Action is required")
	}

	// e.TraceID wins when set so the async chokepoint path (which runs under a fresh background ctx) keeps trace correlation. Sync callers
	// continue to leave it empty and the ctx fallback preserves the wave-1 behavior.
	traceID := e.TraceID
	if traceID == "" {
		traceID = traceIDFromContext(ctx)
	}
	actorEmail := s.resolveActorEmail(ctx, e)

	var payloadBytes []byte
	if len(e.Payload) > 0 {
		var err error
		payloadBytes, err = json.Marshal(e.Payload)
		if err != nil {
			return fmt.Errorf("audit.Record: marshal payload: %w", err)
		}
	}

	const q = `
		INSERT INTO audit_events (
			actor_user_id, actor_email, action, target_type, target_id,
			trace_id, remote_addr, payload
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, q,
		nullInt64(e.UserID),
		nullString(actorEmail),
		string(e.Action),
		nullString(e.TargetType),
		nullString(e.TargetID),
		nullString(traceID),
		nullString(e.RemoteAddr),
		nullBytes(payloadBytes),
	)
	// Dual-emit BEFORE returning on INSERT failure so the observability pipeline always sees a record, even when the DB rejected the row.
	// Per server-identity-audit-log spec: "The dual emit MUST happen even when the database insert fails so the observability pipeline
	// sees a record."
	s.emitDualEmit(ctx, e, actorEmail, traceID)
	if err != nil {
		s.logger.ErrorContext(ctx, "audit row INSERT failed",
			"err", err,
			"action", string(e.Action),
			"target_type", e.TargetType,
			"target_id", e.TargetID,
		)
		if s.writeFailures != nil {
			s.writeFailures.Add(ctx, 1,
				metric.WithAttributes(attribute.String("action", string(e.Action))))
		}
		return fmt.Errorf("audit.Record insert: %w", err)
	}
	return nil
}

// emitDualEmit logs the audit row to slog and sets OTel span attributes on the active request span so a SigNoz / OTLP backend has the
// row's content without a separate audit_events export. The slog level dispatches by spec: INFO when the decision is allow, WARN when
// the decision is deny / error or the action is a break-glass action (every break-glass row is operationally noteworthy because the
// recovery surface is the high-privilege path). Mirrors logDropped's attribute set minus the "reason" key (drops carry queue_full /
// writer_stopped / drain_deadline_exceeded; a successful row has none). Payload is included verbatim when non-empty so dashboards can
// filter on payload.decision (chokepoint allow/deny) and payload.reason (OIDC + break-glass failure mode codes).
func (s *Store) emitDualEmit(ctx context.Context, e api.AuditEvent, actorEmail, traceID string) {
	uid := int64(0)
	if e.UserID != nil {
		uid = *e.UserID
	}
	attrs := []any{
		"action", string(e.Action),
		"target_type", e.TargetType,
		"target_id", e.TargetID,
		"actor_email", actorEmail,
		attrkeys.UserID, uid,
	}
	if traceID != "" {
		attrs = append(attrs, "trace_id", traceID)
	}
	if len(e.Payload) > 0 {
		attrs = append(attrs, "payload", e.Payload)
	}
	level := auditLogLevel(e)
	s.logger.Log(ctx, level, "audit recorded", attrs...)

	// Per server-identity-audit-log spec: every audit emission must set the three edr.audit.* attributes on the active request span.
	// Pulled out of the OTel span (not the slog attrs) so the trace UI can pivot on the same dimensions the SigNoz log query uses,
	// regardless of where the operator entered the dashboard.
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		span.SetAttributes(
			attribute.String("edr.audit.action", string(e.Action)),
			attribute.String("edr.audit.decision", auditDecision(e)),
			attribute.String("edr.audit.reason", auditReason(e)),
		)
	}
}

// auditLogLevel maps an audit event to the slog level the server-identity-audit-log spec mandates: allow -> INFO; deny / error /
// break-glass action -> WARN. The dispatcher accepts both the chokepoint payload shape ({"allow": bool, "reason": string}) and the
// breakglass/oidc payload shape ({"decision": string, "reason": string}) so a single function covers every audit-row producer.
func auditLogLevel(e api.AuditEvent) slog.Level {
	a := string(e.Action)
	// Break-glass actions are operationally noteworthy even on success: the recovery surface is the high-privilege path and every
	// interaction should land in the WARN-or-higher log stream operators monitor.
	if strings.HasPrefix(a, "auth.breakglass.") {
		return slog.LevelWarn
	}
	// Failure / error suffix actions (auth.oidc.failure, auth.oidc.callback.error) are the auth-side "decision=error" shape; emit at WARN
	// so they group with chokepoint denies on the dashboard's "things to investigate" panel.
	if strings.HasSuffix(a, ".failure") || strings.HasSuffix(a, ".error") {
		return slog.LevelWarn
	}
	if p := e.Payload; p != nil {
		if allow, ok := p["allow"].(bool); ok && !allow {
			return slog.LevelWarn
		}
		if d, ok := p["decision"].(string); ok {
			switch d {
			case "deny", "error":
				return slog.LevelWarn
			}
		}
	}
	return slog.LevelInfo
}

// auditDecision extracts the decision string from the audit event's payload, normalizing the two payload shapes the codebase emits
// (chokepoint's {allow: bool} and breakglass/oidc's {decision: str}). Returns "allow" / "deny" / "error" / "unspecified" - the OTel
// attribute lands in SigNoz's traces UI where operators filter on it.
func auditDecision(e api.AuditEvent) string {
	if p := e.Payload; p != nil {
		if allow, ok := p["allow"].(bool); ok {
			if allow {
				return "allow"
			}
			return "deny"
		}
		if d, ok := p["decision"].(string); ok {
			return d
		}
	}
	a := string(e.Action)
	if strings.HasSuffix(a, ".failure") || strings.HasSuffix(a, ".error") {
		return "error"
	}
	if strings.HasSuffix(a, ".success") {
		return "allow"
	}
	return "unspecified"
}

// auditReason extracts the reason string. Empty when no reason is declared on the payload - that's still a valid OTel attribute
// (queries on edr.audit.reason=” surface 'reasonless' rows like user.created which carry no decision context).
func auditReason(e api.AuditEvent) string {
	if p := e.Payload; p != nil {
		if r, ok := p["reason"].(string); ok {
			return r
		}
	}
	return ""
}

// resolveActorEmail returns the email to denormalise onto the audit row. Caller-supplied ActorEmail wins (login paths know the email
// already); otherwise look it up from users by UserID. A failed lookup is not a hard error because the audit row's user_id column
// is still authoritative; we simply leave actor_email empty and let the LEFT JOIN on read surface the live email when the user still
// exists.
func (s *Store) resolveActorEmail(ctx context.Context, e api.AuditEvent) string {
	if e.ActorEmail != "" {
		return e.ActorEmail
	}
	if e.UserID == nil {
		return ""
	}
	var email sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT email FROM users WHERE id = ?`, *e.UserID).Scan(&email); err != nil {
		return ""
	}
	if email.Valid {
		return email.String
	}
	return ""
}

// List returns audit rows matching the filter, newest first. Caller passes a non-zero Limit; the Store caps it at maxListLimit so a
// runaway request cannot scan the whole table.
func (s *Store) List(ctx context.Context, f api.AuditFilter) ([]api.AuditRow, error) {
	limit := f.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = maxListLimit
	}
	where, args := buildListWhere(f)
	args = append(args, limit)

	q := `
		SELECT a.id, a.occurred_at, a.actor_user_id, a.actor_email,
		       a.action, a.target_type, a.target_id, a.trace_id,
		       a.remote_addr, a.payload, COALESCE(u.email, '')
		FROM audit_events a
		LEFT JOIN users u ON u.id = a.actor_user_id ` + where + `
		ORDER BY a.id DESC
		LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit.List query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// CodeQL flags `make([]T, 0, limit)` when limit traces back to a user-controlled value, even though limit is clamped to maxListLimit
	// above. Drop the capacity hint and let the slice grow on demand; audit pages are bounded (LIMIT in the SELECT, max 500 rows),
	// so the few reallocations along the way are not measurable.
	var out []api.AuditRow
	for rows.Next() {
		r, err := scanListRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit.List iter: %w", err)
	}
	return out, nil
}

// buildListWhere builds the WHERE clause + bound args for List. Pulled out of List so the parent function stays at a cognitive
// complexity below Sonar's S3776 threshold; each branch is a single optional filter and is independently testable. The leading `WHERE
// 1=1` is a trivial harness so each clause appends as ` AND ...?` regardless of which other filters are set.
func buildListWhere(f api.AuditFilter) (string, []any) {
	args := make([]any, 0, 8)
	where := "WHERE 1=1"
	if f.UserID != nil {
		where += " AND a.actor_user_id = ?"
		args = append(args, *f.UserID)
	}
	if f.Action != "" {
		where += " AND a.action = ?"
		args = append(args, string(f.Action))
	}
	if f.TargetType != "" {
		where += " AND a.target_type = ?"
		args = append(args, f.TargetType)
	}
	if f.TargetID != "" {
		where += " AND a.target_id = ?"
		args = append(args, f.TargetID)
	}
	if !f.Since.IsZero() {
		where += " AND a.occurred_at >= ?"
		args = append(args, f.Since)
	}
	if !f.Until.IsZero() {
		where += " AND a.occurred_at < ?"
		args = append(args, f.Until)
	}
	if f.BeforeID > 0 {
		where += " AND a.id < ?"
		args = append(args, f.BeforeID)
	}
	return where, args
}

// scanListRow unmarshals one row from List's SELECT into a public AuditRow. Pulled out so List's per-row loop body stays trivial;
// the scan + null-handling logic is the lion's share of the cognitive complexity that S3776 was flagging on the previous in-line
// shape. The caller's row iteration is therefore a one-liner per row, and the scan logic is independently exercised by mysql_test's
// round-trip assertions.
func scanListRow(rows *sql.Rows) (api.AuditRow, error) {
	var (
		r            api.AuditRow
		actorUserID  sql.NullInt64
		actorEmail   sql.NullString
		targetType   sql.NullString
		targetID     sql.NullString
		traceID      sql.NullString
		remoteAddr   sql.NullString
		payloadBytes []byte
		joinedEmail  string
		action       string
	)
	if err := rows.Scan(
		&r.ID, &r.OccurredAt, &actorUserID, &actorEmail,
		&action, &targetType, &targetID, &traceID,
		&remoteAddr, &payloadBytes, &joinedEmail,
	); err != nil {
		return r, fmt.Errorf("audit.List scan: %w", err)
	}
	r.Action = api.AuditAction(action)
	if actorUserID.Valid {
		id := actorUserID.Int64
		r.UserID = &id
	}
	// Prefer the live join so the retrieval endpoint reflects current emails (e.g. an admin who renamed their email post-action sees the
	// new value). Fall back to the denormalised actor_email when the user row no longer exists.
	switch {
	case joinedEmail != "":
		r.UserEmail = joinedEmail
	case actorEmail.Valid:
		r.UserEmail = actorEmail.String
	}
	r.TargetType = targetType.String
	r.TargetID = targetID.String
	r.TraceID = traceID.String
	r.RemoteAddr = remoteAddr.String
	if len(payloadBytes) > 0 {
		payload := map[string]any{}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			return r, fmt.Errorf("audit.List unmarshal payload row=%d: %w", r.ID, err)
		}
		r.Payload = payload
	}
	return r, nil
}

// maxListLimit caps the page size so a runaway retrieval request can't scan the whole table. 500 is well above any realistic admin
// UI page (history grids show 50-100 typically) but small enough to keep the response under a megabyte even with maximally populated
// payloads.
const maxListLimit = 500

func traceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

func nullInt64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
