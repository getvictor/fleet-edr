package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	otrace "go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/audit"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newStore returns a fresh audit Store backed by a test DB. The identity testkit applies users + sessions + audit_events schema,
// so the LEFT JOIN against users in List can resolve actor emails.
func newStore(t *testing.T) (*audit.Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return audit.New(db, nil), db
}

// newStoreWithLogger is like newStore but binds the supplied logger so dual-emit assertions can capture the INFO line. Tests that
// don't care about the slog side use newStore (slog.Default()).
func newStoreWithLogger(t *testing.T, logger *slog.Logger) (*audit.Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return audit.New(db, logger), db
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
	t.Parallel()
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

// The Recorder snapshots the acting principal (id + display label) onto the row at write time, so the row stays attributable with no
// join and survives the user later being deleted. ADR-0017 replaced the live users-table email lookup with this snapshot. The store's
// bridge derives the principal from a legacy UserID/ActorEmail caller until every caller sets Actor directly.
func TestRecord_SnapshotsActorPrincipal(t *testing.T) {
	t.Parallel()
	store, db := newStore(t)
	const userID = int64(99)
	seedUser(t, db, userID, "operator-99@test")

	uid := userID
	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		UserID:     &uid,
		ActorEmail: "operator-99@test",
		Action:     api.AuditAlertAcknowledge,
	}))

	rows, err := store.List(t.Context(), api.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "usr_99", rows[0].Actor.ID)
	assert.Equal(t, api.PrincipalUser, rows[0].Actor.Type)
	assert.Equal(t, "operator-99@test", rows[0].UserEmail, "snapshot label is surfaced as UserEmail for back-compat")

	// The snapshot survives user deletion: no join means the label captured at write time is authoritative.
	_, err = db.ExecContext(t.Context(), `DELETE FROM users WHERE id = ?`, userID)
	require.NoError(t, err)
	rowsAfter, err := store.List(t.Context(), api.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, rowsAfter, 1)
	assert.Equal(t, "operator-99@test", rowsAfter[0].UserEmail,
		"snapshot label must survive user deletion")
}

// TestRecord_SnapshotsServiceAccountPrincipal exercises the principal-model attribution path directly (Actor set, no legacy
// UserID/ActorEmail bridge): a service-account action is recorded with its svc_ principal id and name, and reads back as a
// service_account row with no user id. This is the #514 attribution guarantee for non-human actors.
func TestRecord_SnapshotsServiceAccountPrincipal(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)

	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		Actor:  api.ServiceAccountPrincipal(7, "ci-bot"),
		Action: api.AuditDetectionConfigExclusionCreate,
	}))

	rows, err := store.List(t.Context(), api.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "svc_7", rows[0].Actor.ID)
	assert.Equal(t, api.PrincipalServiceAccount, rows[0].Actor.Type)
	assert.Equal(t, "ci-bot", rows[0].UserEmail, "the service account's name is the snapshot label")
	assert.Nil(t, rows[0].UserID, "a service-account row carries no numeric user id")
}

// login_failed rows have no user_id (the email may be unknown). The retrieval endpoint must surface them with the attempted email so a
// brute-force pattern is observable in retention.
func TestRecord_LoginFailedKeepsEmailWithoutUser(t *testing.T) {
	t.Parallel()
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

// trace_id is pulled from the OTel span on ctx so handler code does not have to thread it explicitly. The span's trace-id ends up in
// the audit row, which lets a reviewer correlate an audit row with the corresponding SigNoz traces / logs by trace-id alone.
func TestRecord_TraceIDFromContext(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// List paginates via the (Limit, BeforeID) cursor: passing the smallest id from page N returns page N+1. We verify the boundary
// condition (cursor row is excluded, not duplicated).
func TestList_Paginates(t *testing.T) {
	t.Parallel()
	store, db := newStore(t)
	seedUser(t, db, 1, "u1@test")

	uid := int64(1)
	for range 5 {
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
	t.Parallel()
	store, _ := newStore(t)
	err := store.Record(t.Context(), api.AuditEvent{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Action is required")
}

// New panics on nil db: a Store with a nil db is a programming error that would only surface at request time (when the user's audit
// row disappears into a nil-pointer panic).
func TestNew_PanicsOnNilDB(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { _ = audit.New(nil, nil) })
}

// Record dual-emits the just-committed audit row to slog at INFO so SigNoz and other OTLP backends have the row's content without a
// separate audit_events export. The line MUST carry the same attribute keys the async-writer drop log uses, so a single dashboard
// query can match success, drop, and failure states uniformly. This test captures the slog handler output and pins the wire shape:
// renaming a key here is renaming a dashboard contract.
func TestRecord_EmitsInfoLogOnSuccess(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, db := newStoreWithLogger(t, logger)

	const userID = int64(7)
	seedUser(t, db, userID, "operator-7@test")
	uid := userID
	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		UserID:     &uid,
		ActorEmail: "operator-7@test",
		Action:     api.AuditAuthLoginSuccess,
		TargetType: "user",
		TargetID:   "7",
		RemoteAddr: "127.0.0.1:54321",
		Payload:    map[string]any{"decision": "allow"},
	}))

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "audit recorded", entry["msg"])
	assert.Equal(t, "INFO", entry["level"])
	assert.Equal(t, "auth.login.success", entry["action"])
	assert.Equal(t, "user", entry["target_type"])
	assert.Equal(t, "7", entry["target_id"])
	assert.Equal(t, "operator-7@test", entry["actor_label"])
	assert.Equal(t, "usr_7", entry["actor_principal_id"])
	assert.InDelta(t, float64(userID), entry["edr.user.id"], 0)

	payload, ok := entry["payload"].(map[string]any)
	require.True(t, ok, "payload must serialize as a nested object so SigNoz can index payload.decision")
	assert.Equal(t, "allow", payload["decision"])
}

// spec:server-identity-audit-log/audit-rows-are-dual-emitted-to-slog-and-otel/allow-emits-info
//
// Pins both THEN clauses of the allow-emits-INFO scenario: an authorization allow on a state-changing action (authz.host.isolate
// with payload.allow=true) writes a structured slog record at INFO carrying the audit fields, AND the active request span carries
// the three edr.audit.* attributes (action, decision, reason). The span is captured via an in-memory SpanRecorder on a LOCAL
// TracerProvider so the test reads exactly the attributes emitDualEmit set on trace.SpanFromContext(ctx).
func TestRecord_AllowEmitsInfoAndSpanAttributes(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, db := newStoreWithLogger(t, logger)
	const userID = int64(13)
	seedUser(t, db, userID, "operator-13@test")

	rec := tracetest.NewSpanRecorder()
	tp := trace.NewTracerProvider(trace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("audit-allow-test").Start(t.Context(), "request")

	uid := userID
	require.NoError(t, store.Record(ctx, api.AuditEvent{
		UserID:     &uid,
		ActorEmail: "operator-13@test",
		Action:     api.AuditAction("authz.host.isolate"),
		TargetType: "host",
		TargetID:   "h-1",
		Payload:    map[string]any{"allow": true, "reason": "granted"},
	}))
	span.End()

	// slog INFO clause. Scan the emitted JSON lines for the decision record rather than assuming the buffer holds exactly one entry, so
	// the assertion stays valid if the store ever emits additional log lines around the decision.
	var entry map[string]any
	for line := range bytes.SplitSeq(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal(line, &rec))
		if rec["action"] == "authz.host.isolate" {
			entry = rec
			break
		}
	}
	require.NotNil(t, entry, "expected a slog record for the authz.host.isolate decision")
	assert.Equal(t, "INFO", entry["level"], "allow decision must emit slog at INFO")
	assert.Equal(t, "authz.host.isolate", entry["action"])

	// OTel span-attribute clause.
	ended := rec.Ended()
	require.Len(t, ended, 1, "exactly one span must have ended")
	attrs := map[string]string{}
	for _, kv := range ended[0].Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	assert.Equal(t, "authz.host.isolate", attrs["edr.audit.action"])
	assert.Equal(t, "allow", attrs["edr.audit.decision"])
	assert.Equal(t, "granted", attrs["edr.audit.reason"])
}

// When UserID is nil (e.g. a pre-auth audit row like auth.oidc.callback.error), the dual-emit still fires and emits edr.user.id=0.
// The audit row itself stays attributable via the actor_email column. Per server-identity-audit-log spec, failure suffix actions land
// at WARN so a SigNoz alert on severity_text=WARN catches them without a separate filter.
func TestRecord_EmitsWarnLogForFailureAction(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, _ := newStoreWithLogger(t, logger)

	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		ActorEmail: "operator@test",
		Action:     api.AuditAction("auth.oidc.failure"),
		Payload:    map[string]any{"reason": "oidc.unknown_subject"},
	}))

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "audit recorded", entry["msg"])
	assert.Equal(t, "WARN", entry["level"],
		"server-identity-audit-log spec: error decision must emit slog at WARN")
	assert.Equal(t, "auth.oidc.failure", entry["action"])
	assert.Equal(t, "operator@test", entry["actor_label"], "the attempted identifier is recorded as the actor label")
	_, hasUID := entry["edr.user.id"]
	assert.False(t, hasUID, "a pre-auth failure has no user principal, so edr.user.id must not be emitted")
}

// Spec contract: a chokepoint deny emits slog at WARN. Pinned so the observability dashboard's "WARN threshold" alert catches
// chokepoint denies without a separate severity filter per decision type. server-identity-audit-log spec §"Audit rows are
// dual-emitted": "WARN when the decision is `deny`, the action is a break-glass action, or the decision is `error`."
// spec:server-identity-audit-log/audit-rows-are-dual-emitted-to-slog-and-otel/deny-emits-warn
func TestRecord_EmitsWarnLogOnChokepointDeny(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, db := newStoreWithLogger(t, logger)
	uid := int64(11)
	seedUser(t, db, uid, "denied@test")

	require.NoError(t, store.Record(t.Context(), api.AuditEvent{
		UserID:     &uid,
		ActorEmail: "denied@test",
		Action:     api.AuditAction("authz.host.isolate"),
		TargetType: "host",
		TargetID:   "h-1",
		Payload:    map[string]any{"allow": false, "reason": "no_matching_rule"},
	}))

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "WARN", entry["level"],
		"chokepoint deny (payload.allow=false) must emit slog at WARN per spec")
	assert.Equal(t, "authz.host.isolate", entry["action"])
}

// Spec contract: every break-glass action emits slog at WARN regardless of outcome, because the recovery surface is the
// high-privilege path and every interaction is operationally noteworthy. server-identity-audit-log spec: "WARN when ... the action is
// a break-glass action."
//
// spec:server-identity-authentication/break-glass-authentication-is-rate-limited-and-audited-at-warn/successful-break-glass-emits-a-warn-audit-row
//
// The auth.breakglass.success subtest pins the scenario's core: a successful break-glass login lands an audit row at WARN with
// action='auth.breakglass.success', which is exactly what the SigNoz "any break-glass success" alert keys on.
func TestRecord_EmitsWarnLogForBreakglassActions(t *testing.T) {
	t.Parallel()
	cases := []api.AuditAction{
		api.AuditAuthBreakglassBootstrap,
		api.AuditAuthBreakglassSuccess,
		api.AuditAuthBreakglassFailure,
	}
	for _, action := range cases {
		t.Run(string(action), func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
			store, _ := newStoreWithLogger(t, logger)
			require.NoError(t, store.Record(t.Context(), api.AuditEvent{
				ActorEmail: "admin@fleet-edr.local",
				Action:     action,
				TargetType: "user",
				TargetID:   "1",
			}))
			var entry map[string]any
			require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
			assert.Equal(t, "WARN", entry["level"],
				"break-glass action %q must emit slog at WARN per spec", string(action))
		})
	}
}

// Spec contract: the dual emit MUST happen even when the DB INSERT fails. Closes the observability gap where a transient DB outage
// erases the audit row's content from the OTel log stream. server-identity-audit-log spec: "The dual emit MUST happen even when the
// database insert fails so the observability pipeline sees a record."
func TestRecord_DualEmitFiresEvenOnInsertFailure(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, db := newStoreWithLogger(t, logger)

	// Force INSERT failure by violating the action NOT NULL constraint via a NULL UserID + missing required column. Simpler: close the db
	// connection so the ExecContext fails fast with a known error.
	require.NoError(t, db.Close())

	err := store.Record(t.Context(), api.AuditEvent{
		ActorEmail: "operator@test",
		Action:     api.AuditAction("authz.host.read"),
		Payload:    map[string]any{"allow": false, "reason": "no_matching_rule"},
	})
	require.Error(t, err, "INSERT against a closed DB must surface as an error")

	// The dual-emit + the ERROR-level "INSERT failed" message should
	// both be in the buffer; the audit-row content is preserved.
	entries := parseJSONLogs(t, buf.Bytes())
	require.GreaterOrEqual(t, len(entries), 2, "expected dual-emit + ERROR log; got %d", len(entries))

	var sawAuditRecorded, sawInsertFailed bool
	for _, e := range entries {
		switch e["msg"] {
		case "audit recorded":
			sawAuditRecorded = true
			assert.Equal(t, "authz.host.read", e["action"])
			assert.Equal(t, "WARN", e["level"], "deny decision must still be WARN even on insert failure")
		case "audit row INSERT failed":
			sawInsertFailed = true
			assert.Equal(t, "ERROR", e["level"])
		}
	}
	assert.True(t, sawAuditRecorded, "dual-emit must fire even on INSERT failure")
	assert.True(t, sawInsertFailed, "INSERT failure must emit a separate ERROR log")
}

// spec:server-identity-audit-log/authentication-outcomes-write-an-audit-row/audit-write-failure-does-not-fail-the-user-request
//
// Pins the failure-handling clauses of the scenario: when the audit INSERT fails (transient DB outage simulated by a closed
// connection), Record (a) logs the failure at ERROR with a unique structured key ("audit row INSERT failed") and (b) increments
// the edr.audit.write_failures counter. The counter is registered against the global OTel meter, so the test installs a
// ManualReader-backed MeterProvider as the global before constructing the Store, then collects it after the forced failure. The
// scenario's "the user request still completes" clause is structural: login handlers mint the session before calling the audit
// recorder and never propagate Record's error to the user response (the recorder is fire-and-forget on the request's critical path).
func TestRecord_WriteFailureLogsErrorAndIncrementsMetric(t *testing.T) { //nolint:paralleltest // reads process-global OTel meter counter
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Install a ManualReader-backed global MeterProvider so the audit Store's package-level otel.Meter counter records into a
	// reader this test can collect. Restore the prior global provider on cleanup so we don't leak global state into sibling tests.
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		otel.SetMeterProvider(prev)
		_ = mp.Shutdown(context.Background())
	})

	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	store := audit.New(db, logger) // registers the write-failures counter against the global meter installed above

	// Force the INSERT to fail by closing the connection pool.
	require.NoError(t, db.Close())

	err := store.Record(t.Context(), api.AuditEvent{
		ActorEmail: "operator@test",
		Action:     api.AuditAuthLoginSuccess,
		Payload:    map[string]any{"decision": "allow"},
	})
	require.Error(t, err, "INSERT against a closed DB must surface as an error to the recorder")

	// (a) ERROR log with the unique structured key.
	var sawInsertFailed bool
	for _, e := range parseJSONLogs(t, buf.Bytes()) {
		if e["msg"] == "audit row INSERT failed" {
			sawInsertFailed = true
			assert.Equal(t, "ERROR", e["level"])
		}
	}
	assert.True(t, sawInsertFailed, "write failure must emit an ERROR log with key 'audit row INSERT failed'")

	// (b) edr.audit.write_failures counter incremented by exactly one for this action.
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var total int64
	var found bool
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "edr.audit.write_failures" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok, "write_failures must be an int64 Sum")
			found = true
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
		}
	}
	require.True(t, found, "edr.audit.write_failures metric must be present after a failed insert")
	assert.Equal(t, int64(1), total, "edr.audit.write_failures must increment by exactly one on a single failed insert")
}

// parseJSONLogs splits a buffer's JSON-per-line slog output into a slice of decoded maps. Pulled out so the dual-emit-on-failure test
// stays focused on the property being verified.
func parseJSONLogs(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for line := range bytes.SplitSeq(raw, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry map[string]any
		require.NoError(t, json.Unmarshal(line, &entry), "line: %s", line)
		entries = append(entries, entry)
	}
	return entries
}

// Sanity: the action constants are stable strings. Anyone changing them is renaming wire-shape contracts, and this test fails loudly
// so the rename gets caught at code-review time.
func TestAuditAction_StableConstants(t *testing.T) {
	t.Parallel()
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
		{api.AuditCommandIssue, "command.issue"},
		{api.AuditEnrollmentRevoke, "enrollment.revoke"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, string(tc.got))
	}
	// Sanity quick-fail if the package is compiled with the wrong context.
	_ = context.TODO
}
