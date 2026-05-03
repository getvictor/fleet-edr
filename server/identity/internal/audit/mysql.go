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

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/identity/api"
)

// Store implements both api.AuditRecorder and api.AuditReader against
// MySQL. Constructed once at boot from bootstrap.New and shared across
// every audit-emitting handler in the process.
type Store struct {
	db *sqlx.DB
}

// New returns a Store. Panics if db is nil because a Store with a nil
// db is a programming error that would only surface at request time.
func New(db *sqlx.DB) *Store {
	if db == nil {
		panic("audit.New: db must not be nil")
	}
	return &Store{db: db}
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

	traceID := traceIDFromContext(ctx)
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
	if err != nil {
		return fmt.Errorf("audit.Record insert: %w", err)
	}
	return nil
}

// resolveActorEmail returns the email to denormalise onto the audit row.
// Caller-supplied ActorEmail wins (login paths know the email already);
// otherwise look it up from users by UserID. A failed lookup is not a
// hard error because the audit row's user_id column is still
// authoritative; we simply leave actor_email empty and let the LEFT
// JOIN on read surface the live email when the user still exists.
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

// List returns audit rows matching the filter, newest first. Caller
// passes a non-zero Limit; the Store caps it at maxListLimit so a
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

	out := make([]api.AuditRow, 0, limit)
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

// buildListWhere builds the WHERE clause + bound args for List. Pulled
// out of List so the parent function stays at a cognitive complexity
// below Sonar's S3776 threshold; each branch is a single optional
// filter and is independently testable. The leading `WHERE 1=1` is a
// trivial harness so each clause appends as ` AND ...?` regardless of
// which other filters are set.
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

// scanListRow unmarshals one row from List's SELECT into a public
// AuditRow. Pulled out so List's per-row loop body stays trivial; the
// scan + null-handling logic is the lion's share of the cognitive
// complexity that S3776 was flagging on the previous in-line shape.
// The caller's row iteration is therefore a one-liner per row, and the
// scan logic is independently exercised by mysql_test's round-trip
// assertions.
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
	// Prefer the live join so the retrieval endpoint reflects current
	// emails (e.g. an admin who renamed their email post-action sees
	// the new value). Fall back to the denormalised actor_email when
	// the user row no longer exists.
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

// maxListLimit caps the page size so a runaway retrieval request can't
// scan the whole table. 500 is well above any realistic admin UI page
// (history grids show 50-100 typically) but small enough to keep the
// response under a megabyte even with maximally populated payloads.
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
