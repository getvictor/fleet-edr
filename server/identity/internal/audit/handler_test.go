package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/audit"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// stubReader is a deterministic api.AuditReader for handler tests. captures the AuditFilter the handler computed so each test can
// assert "the query string parsed into this filter" without setting up a DB.
type stubReader struct {
	rows       []api.AuditRow
	err        error
	gotFilter  api.AuditFilter
	calledOnce bool
}

func (s *stubReader) List(_ context.Context, f api.AuditFilter) ([]api.AuditRow, error) {
	s.gotFilter = f
	s.calledOnce = true
	return s.rows, s.err
}

// allowAllAuthZ is the default chokepoint stub for handler tests that are not exercising the authz gate. Returns Allow=true so the
// test flows past authzGate and into the parse / read / response code under test. Allow + deny paths get their own dedicated tests
// against the real engine.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: true, Reason: "granted"}, nil
}

// stubAuthZ lets a test pin a specific decision (or error) on the
// chokepoint without standing up the real Rego engine.
type stubAuthZ struct {
	decision api.Decision
	err      error
}

func (s stubAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return s.decision, s.err
}

func newHandlerTestServer(t *testing.T, reader api.AuditReader) *httptest.Server {
	t.Helper()
	return newHandlerTestServerWithAuthZ(t, reader, allowAllAuthZ{})
}

func newHandlerTestServerWithAuthZ(t *testing.T, reader api.AuditReader, az api.AuthZ) *httptest.Server {
	t.Helper()
	h := audit.NewHandler(reader, az, slog.Default())
	mux := http.NewServeMux()
	h.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Empty result → 200 with `{"items":[]}` (not null, not omitted) so the
// admin UI can iterate without a nil guard.
func TestHandler_ListEmptySuccess(t *testing.T) {
	t.Parallel()
	reader := &stubReader{rows: nil}
	srv := newHandlerTestServer(t, reader)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var got struct {
		Items []api.AuditRow `json:"items"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Empty(t, got.Items)
	assert.True(t, reader.calledOnce)
}

// Successful read with rows is forwarded byte-for-byte; payload, action,
// trace_id, and target survive marshalling.
func TestHandler_ListPopulated(t *testing.T) {
	t.Parallel()
	uid := int64(7)
	reader := &stubReader{rows: []api.AuditRow{{
		ID:         42,
		OccurredAt: time.Date(2026, 5, 3, 18, 0, 0, 0, time.UTC),
		UserID:     &uid,
		UserEmail:  "operator@example.test",
		Action:     api.AuditAlertAcknowledge,
		TargetType: "alert",
		TargetID:   "34",
		TraceID:    "abcd",
		RemoteAddr: "127.0.0.1:1",
		Payload:    map[string]any{"new_status": "acknowledged"},
	}}}
	srv := newHandlerTestServer(t, reader)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events?limit=1", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var got struct {
		Items []api.AuditRow `json:"items"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Len(t, got.Items, 1)
	assert.Equal(t, api.AuditAlertAcknowledge, got.Items[0].Action)
	assert.Equal(t, "alert", got.Items[0].TargetType)
	assert.Equal(t, "34", got.Items[0].TargetID)
	assert.Equal(t, "operator@example.test", got.Items[0].UserEmail)
	assert.Equal(t, "acknowledged", got.Items[0].Payload["new_status"])
	assert.Equal(t, 1, reader.gotFilter.Limit)
}

// Each query-param parse error must surface a 400 with a stable wire code and MUST NOT touch the reader (no point hitting the DB for a
// malformed request) and MUST NOT be tagged as an authn failure.
func TestHandler_ListParseErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		query    string
		wantCode string
	}{
		{"bad user_id", "user_id=notanumber", "bad_user_id"},
		{"bad since", "since=yesterday", "bad_since"},
		{"bad until", "until=tomorrow", "bad_until"},
		{"bad limit non-numeric", "limit=ten", "bad_limit"},
		{"bad limit zero", "limit=0", "bad_limit"},
		{"bad before_id non-numeric", "before_id=foo", "bad_before_id"},
		{"bad before_id zero", "before_id=0", "bad_before_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := &stubReader{}
			srv := newHandlerTestServer(t, reader)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events?"+tc.query, nil)
			require.NoError(t, err)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			// Regression for #80 review: validation 400s must not advertise a Bearer challenge AND must not flow through
			// WriteCookieAuthFailure (which would tag the OTel span as auth.result=fail and emit a `Warn authn failed` log
			// line for what is actually a query-string parse error).
			assert.Empty(t, resp.Header.Get("WWW-Authenticate"))

			body, _ := io.ReadAll(resp.Body)
			var got map[string]string
			require.NoError(t, json.Unmarshal(body, &got))
			assert.Equal(t, tc.wantCode, got["error"])
			assert.False(t, reader.calledOnce, "reader should not run on parse error")
		})
	}
}

// Filter parsing roundtrips: every supported field maps from query string onto the AuditFilter the reader sees. Catches future
// regressions where adding a new filter forgets to plumb the URL parameter or vice versa.
func TestHandler_ListFilterParsing(t *testing.T) {
	t.Parallel()
	reader := &stubReader{}
	srv := newHandlerTestServer(t, reader)

	q := "user_id=42&action=alert.acknowledge&target_type=alert&target_id=99" +
		"&since=2026-05-01T00:00:00Z&until=2026-05-04T00:00:00Z" +
		"&limit=25&before_id=1000"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events?"+q, nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := reader.gotFilter
	require.NotNil(t, got.UserID)
	assert.Equal(t, int64(42), *got.UserID)
	assert.Equal(t, api.AuditAlertAcknowledge, got.Action)
	assert.Equal(t, "alert", got.TargetType)
	assert.Equal(t, "99", got.TargetID)
	assert.Equal(t, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), got.Since.UTC())
	assert.Equal(t, time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC), got.Until.UTC())
	assert.Equal(t, 25, got.Limit)
	assert.Equal(t, int64(1000), got.BeforeID)
}

// A reader error is a 500, not an auth failure; the body still uses the project's `{"error":"code"}` shape so scripted clients have
// one schema to parse for both 4xx and 5xx.
func TestHandler_ListReaderError(t *testing.T) {
	t.Parallel()
	reader := &stubReader{err: errors.New("clickhouse went away")}
	srv := newHandlerTestServer(t, reader)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))

	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "internal", got["error"])
}

func TestNewHandler_PanicsOnNilReader(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { _ = audit.NewHandler(nil, allowAllAuthZ{}, slog.Default()) })
}

// authz must be supplied; a Handler without one cannot enforce the chokepoint and would silently grant every read once a session
// middleware places an actor on ctx.
func TestNewHandler_PanicsOnNilAuthZ(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { _ = audit.NewHandler(&stubReader{}, nil, slog.Default()) })
}

// Nil logger is permitted (slog.Default fallback). A handler that
// panics on a missing logger is a footgun for early-boot code paths.
func TestNewHandler_NilLoggerOK(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() { _ = audit.NewHandler(&stubReader{}, allowAllAuthZ{}, nil) })
}

// recordingAudit captures every audit row the chokepoint writes so the audit-of-audit assertion can confirm the read produced an
// `authz.audit.read` row.
type recordingAudit struct {
	mu     sync.Mutex
	events []api.AuditEvent
}

func (r *recordingAudit) Record(_ context.Context, e api.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingAudit) snapshot() []api.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]api.AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

// withActor wraps a handler so every request carries the given actor on its context, standing in for the identity Session
// middleware that pins the actor + role bindings in production.
func withActor(actor *api.Actor, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(api.WithActor(r.Context(), actor)))
	})
}

// spec:server-identity-audit-log/audit-log-read-endpoint-requires-audit-read-and-audits-its-own-access/auditor-reads-the-audit-log
//
// End-to-end against the REAL Rego chokepoint (not a stub): an auditor-bound session reads GET /api/audit-events?limit=50 and gets
// 200 with the rows the reader returns, AND the read itself produces an audit row. The chokepoint emits the audit-of-audit row as
// `authz.audit.read` (audit.read is exempt from the read-sampling gate), which is the implementation of the scenario's "the read
// itself produces an audit row with action='authz.audit.read'" clause.
func TestHandler_AuditorReadIsAuditedThroughRealChokepoint(t *testing.T) {
	t.Parallel()
	rec := &recordingAudit{}
	engine, err := authz.New(t.Context(), rec, nil, authz.Options{})
	require.NoError(t, err)

	uid := int64(1)
	reader := &stubReader{rows: []api.AuditRow{
		{ID: 2, Action: api.AuditAuthLoginSuccess},
		{ID: 1, Action: api.AuditAuthLogout},
	}}
	h := audit.NewHandler(reader, engine, slog.Default())
	mux := http.NewServeMux()
	h.RegisterAuthedRoutes(mux)

	auditor := &api.Actor{
		Principal:    api.UserPrincipal(uid, "auditor@example.test"),
		AuthMethod:   "oidc",
		SessionFresh: true,
		Roles: []api.RoleBinding{{
			UserID: uid, RoleID: "auditor",
			ScopeType: api.RoleBindingScopeGlobal, ScopeID: api.RoleBindingScopeWildcard,
		}},
	}
	srv := httptest.NewServer(withActor(auditor, mux))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events?limit=50", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got listResponseBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Items, 2)
	// Reverse-chronological: the reader returns newest-first and the handler forwards order verbatim.
	assert.Greater(t, got.Items[0].ID, got.Items[1].ID)
	assert.Equal(t, 50, reader.gotFilter.Limit)

	// The chokepoint recorded the audit-of-audit row for this read.
	events := rec.snapshot()
	require.Len(t, events, 1, "auditor read must produce exactly one audit-of-audit row")
	assert.Equal(t, api.AuditAction("authz.audit.read"), events[0].Action)
}

type listResponseBody struct {
	Items []api.AuditRow `json:"items"`
}

// AuthZ deny short-circuits before the reader is hit. The deny reason surfaces on the X-Edr-Authz-Reason header so the operator UI can
// distinguish "forbidden by policy" from "session expired" without parsing a body shape that already varies by error class.
// spec:server-identity-audit-log/audit-log-read-endpoint-requires-audit-read-and-audits-its-own-access/analyst-is-denied-the-audit-log
func TestHandler_AuthZDeny(t *testing.T) {
	t.Parallel()
	reader := &stubReader{}
	srv := newHandlerTestServerWithAuthZ(t, reader,
		stubAuthZ{decision: api.Decision{Allow: false, Reason: "no_matching_rule"}})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "no_matching_rule", resp.Header.Get("X-Edr-Authz-Reason"))
	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "forbidden", got["error"])
	assert.False(t, reader.calledOnce, "reader must not run when authz denies")
}

// AuthZ engine failure is a 503 (transient) and surfaces a stable wire code so the UI's retry semantics for 5xx are exercised, not the
// 401-on-403 redirect-to-login that 4xx triggers.
func TestHandler_AuthZEngineError(t *testing.T) {
	t.Parallel()
	reader := &stubReader{}
	srv := newHandlerTestServerWithAuthZ(t, reader,
		stubAuthZ{err: errors.New("opa exploded")})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/audit-events", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "authz_unavailable", got["error"])
	assert.False(t, reader.calledOnce, "reader must not run on engine error")
}
