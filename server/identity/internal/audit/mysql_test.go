package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace"
	otrace "go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/audit"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newStore returns a fresh audit Store backed by a test DB. The
// identity testkit applies users + sessions + audit_events schema, so
// the LEFT JOIN against users in List can resolve actor emails.
func newStore(t *testing.T) (*audit.Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return audit.New(db), db
}

// seedUser inserts a users row so audit rows that reference it can be
// joined to surface actor_email on retrieval.
func seedUser(t *testing.T, db *sqlx.DB, id int64, email string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)`,
		id, email, []byte("stub-hash"), []byte("stub-salt"))
	require.NoError(t, err)
}

func TestRecord_RoundTrip(t *testing.T) {
	store, db := newStore(t)
	const userID = int64(1)
	seedUser(t, db, userID, "admin@fleet-edr.local")

	uid := userID
	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		UserID:     &uid,
		ActorEmail: "admin@fleet-edr.local",
		Action:     api.AuditAuthLoginSuccess,
		RemoteAddr: "127.0.0.1:54321",
		Payload:    map[string]any{"reason": "n/a"},
	}))

	rows, err := store.List(t.Context(), api.AuditFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	r := rows[0]
	assert.Equal(t, api.AuditAuthLoginSuccess, r.Action)
	assert.Equal(t, "admin@fleet-edr.local", r.UserEmail, "live email comes from JOIN")
	require.NotNil(t, r.UserID)
	assert.Equal(t, userID, *r.UserID)
	assert.Equal(t, "127.0.0.1:54321", r.RemoteAddr)
	assert.Equal(t, "n/a", r.Payload["reason"])
	assert.WithinDuration(t, time.Now(), r.OccurredAt, 30*time.Second)
}

// When the caller does not supply ActorEmail, the Recorder must look it
// up from the users table by UserID and denormalise it onto the row so
// the audit row stays attributable after the user is later deleted.
// This is the key durability promise behind the cross-context recordX
// helpers, which only have user_id from ctx (no email).
func TestRecord_AutoResolvesActorEmailFromUserID(t *testing.T) {
	store, db := newStore(t)
	const userID = int64(99)
	seedUser(t, db, userID, "operator-99@test")

	uid := userID
	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		UserID: &uid,
		Action: api.AuditAlertAcknowledge,
		// ActorEmail intentionally empty; Recorder should fill it from the users row.
	}))

	rows, err := store.List(t.Context(), api.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "operator-99@test", rows[0].UserEmail)

	// And after the user is deleted, the denormalised email survives so
	// the audit row stays attributable. Pre-deletion the LEFT JOIN
	// returns the live email; post-deletion the join is empty and the
	// reader falls back to the actor_email column captured at record time.
	_, err = db.ExecContext(t.Context(), `DELETE FROM users WHERE id = ?`, userID)
	require.NoError(t, err)
	rowsAfter, err := store.List(t.Context(), api.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, rowsAfter, 1)
	assert.Equal(t, "operator-99@test", rowsAfter[0].UserEmail,
		"denormalised actor_email must survive user deletion")
}

// login_failed rows have no user_id (the email may be unknown). The
// retrieval endpoint must surface them with the attempted email so a
// brute-force pattern is observable in retention.
func TestRecord_LoginFailedKeepsEmailWithoutUser(t *testing.T) {
	store, _ := newStore(t)

	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		ActorEmail: "stranger@example.test",
		Action:     api.AuditAuthLoginFailed,
		RemoteAddr: "203.0.113.1:11111",
		Payload:    map[string]any{"reason": "user_not_found"},
	}))

	rows, err := store.List(t.Context(), api.AuditFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].UserID)
	assert.Equal(t, "stranger@example.test", rows[0].UserEmail,
		"actor_email column populated even when no users row exists")
	assert.Equal(t, "user_not_found", rows[0].Payload["reason"])
}

// trace_id is pulled from the OTel span on ctx so handler code does not
// have to thread it explicitly. The span's trace-id ends up in the
// audit row, which lets a reviewer correlate an audit row with the
// corresponding SigNoz traces / logs by trace-id alone.
func TestRecord_TraceIDFromContext(t *testing.T) {
	store, _ := newStore(t)

	tp := trace.NewTracerProvider()
	tracer := tp.Tracer("audit-test")
	ctx, span := tracer.Start(t.Context(), "test-span")
	t.Cleanup(func() { span.End() })

	require.NoError(t, store.Record(ctx, api.AuditEvent{
		Action: api.AuditAuthLoginFailed,
	}))

	rows, err := store.List(t.Context(), api.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, rows, 1)

	want := otrace.SpanFromContext(ctx).SpanContext().TraceID().String()
	assert.Equal(t, want, rows[0].TraceID)
}

// List filters by action so the admin UI can scope to "all logins" or
// "all alert acks" etc.
func TestList_FilterByAction(t *testing.T) {
	store, db := newStore(t)
	seedUser(t, db, 1, "u1@test")

	uid := int64(1)
	require.NoError(t, store.Record(t.Context(), api.AuditEvent{UserID: &uid, Action: api.AuditAuthLoginSuccess}))
	require.NoError(t, store.Record(t.Context(), api.AuditEvent{UserID: &uid, Action: api.AuditAuthLogout}))
	require.NoError(t, store.Record(t.Context(), api.AuditEvent{UserID: &uid, Action: api.AuditAuthLogout}))

	logouts, err := store.List(t.Context(), api.AuditFilter{Action: api.AuditAuthLogout, Limit: 10})
	require.NoError(t, err)
	assert.Len(t, logouts, 2)
	for _, r := range logouts {
		assert.Equal(t, api.AuditAuthLogout, r.Action)
	}
}

// List paginates via the (Limit, BeforeID) cursor: passing the smallest
// id from page N returns page N+1. We verify the boundary condition
// (cursor row is excluded, not duplicated).
func TestList_Paginates(t *testing.T) {
	store, db := newStore(t)
	seedUser(t, db, 1, "u1@test")

	uid := int64(1)
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Record(t.Context(), api.AuditEvent{
			UserID: &uid, Action: api.AuditAuthLoginSuccess,
		}))
	}

	page1, err := store.List(t.Context(), api.AuditFilter{Limit: 2})
	require.NoError(t, err)
	require.Len(t, page1, 2)

	page2, err := store.List(t.Context(), api.AuditFilter{Limit: 2, BeforeID: page1[len(page1)-1].ID})
	require.NoError(t, err)
	require.Len(t, page2, 2)

	// No row appears in both pages.
	for _, a := range page1 {
		for _, b := range page2 {
			assert.NotEqual(t, a.ID, b.ID, "pages must not overlap")
		}
	}
	// Pages descend by id (newest first).
	assert.Greater(t, page1[0].ID, page2[0].ID)
}

// Record requires a non-empty Action; an empty action is a programming
// error caught at the boundary so it does not produce mystery rows.
func TestRecord_RejectsEmptyAction(t *testing.T) {
	store, _ := newStore(t)
	err := store.Record(t.Context(), api.AuditEvent{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Action is required")
}

// New panics on nil db: a Store with a nil db is a programming error
// that would only surface at request time (when the user's audit row
// disappears into a nil-pointer panic).
func TestNew_PanicsOnNilDB(t *testing.T) {
	assert.Panics(t, func() { _ = audit.New(nil) })
}

// Sanity: the action constants are stable strings — anyone changing
// them is renaming wire-shape contracts, and this test fails loudly so
// the rename gets caught at code-review time.
func TestAuditAction_StableConstants(t *testing.T) {
	cases := []struct {
		got  api.AuditAction
		want string
	}{
		{api.AuditAuthLoginSuccess, "auth.login.success"},
		{api.AuditAuthLoginFailed, "auth.login.failed"},
		{api.AuditAuthLogout, "auth.logout"},
		{api.AuditAlertAcknowledge, "alert.acknowledge"},
		{api.AuditAlertResolve, "alert.resolve"},
		{api.AuditAlertReopen, "alert.reopen"},
		{api.AuditPolicyCreate, "policy.create"},
		{api.AuditPolicyUpdate, "policy.update"},
		{api.AuditPolicyDelete, "policy.delete"},
		{api.AuditCommandIssue, "command.issue"},
		{api.AuditEnrollmentRevoke, "enrollment.revoke"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, string(tc.got))
	}
	// Sanity quick-fail if the package is compiled with the wrong context.
	_ = context.TODO
}
