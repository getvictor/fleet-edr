//go:build integration

package oidc_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/identities"
	"github.com/fleetdm/edr/server/identity/internal/oidc"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// fakeIDPClient is the test seam for *oidc.Client. Production code
// uses the real go-oidc-backed client; tests inject a deterministic
// stub so the callback's happy path can be walked without spinning
// up discovery + signing keys.
type fakeIDPClient struct {
	authURL  string
	claims   *oidc.Claims
	exchange error
}

func (f *fakeIDPClient) AuthURL(state, _, _ string) string {
	if f.authURL == "" {
		return "https://idp.example.com/authorize?state=" + state
	}
	return f.authURL
}

func (f *fakeIDPClient) Exchange(_ context.Context, _, _, _ string) (*oidc.Claims, error) {
	if f.exchange != nil {
		return nil, f.exchange
	}
	return f.claims, nil
}

// recAudit collects audit rows so each test asserts the spec-pinned
// action + payload without a MySQL round-trip.
type recAudit struct{ events []api.AuditEvent }

func (r *recAudit) Record(_ context.Context, e api.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

// callbackTestEnv bundles the wired-up dependencies a callback test
// needs.
type callbackTestEnv struct {
	db         *sqlx.DB
	handler    *oidc.Handler
	idp        *fakeIDPClient
	rec        *recAudit
	signingKey []byte
	now        time.Time
}

func newCallbackEnv(t *testing.T, jitEnabled bool, claims *oidc.Claims) *callbackTestEnv {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))

	usersStore := users.New(db)
	identitiesStore := identities.New(db)
	rbacStore := rbac.New(db)
	sessionsStore := sessions.New(db, sessions.Options{})
	rec := &recAudit{}
	prov := oidc.NewProvisioner(db, usersStore, identitiesStore, rbacStore, rec, oidc.ProvisionerOptions{
		AllowJIT: jitEnabled,
	})

	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	idp := &fakeIDPClient{claims: claims}
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	h := oidc.NewHandlerForTest(idp, prov, sessionsStore, signingKey, rec, logger)
	return &callbackTestEnv{
		db: db, handler: h, idp: idp, rec: rec,
		signingKey: signingKey, now: time.Now(),
	}
}

// testWriter routes slog output through t.Log so failures show context.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func (e *callbackTestEnv) callbackRequest(t *testing.T, stateOverride string) *http.Request {
	t.Helper()
	cookieVal, err := oidc.EncodeStateClaim(e.signingKey, "STATE", "NONCE", "VERIFIER", "/ui/", e.now)
	require.NoError(t, err)
	state := "STATE"
	if stateOverride != "" {
		state = stateOverride
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET",
		"/api/auth/callback?state="+state+"&code=AUTHCODE", nil)
	r.AddCookie(&http.Cookie{Name: oidc.StateCookieName, Value: cookieVal})
	return r
}

// Happy path: state cookie verifies, code exchanges, JIT runs (subject
// is fresh, JIT enabled), session minted, response is a 302 to the
// state's pinned redirect with both cookies set. Audits one
// auth.oidc.success row plus one user.created row from the
// provisioner.
func TestHandleCallback_HappyPath_JITNewUser(t *testing.T) {
	env := newCallbackEnv(t, true, &oidc.Claims{
		Subject: "okta-happy",
		Email:   "happy@example.com",
		Name:    "Happy",
	})
	r := env.callbackRequest(t, "")
	w := httptest.NewRecorder()

	env.handler.HandleCallbackForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/ui/", resp.Header.Get("Location"))

	var sessCookie, stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case api.SessionCookieName:
			sessCookie = c
		case oidc.StateCookieName:
			stateCookie = c
		}
	}
	require.NotNil(t, sessCookie, "session cookie must be set")
	assert.True(t, sessCookie.HttpOnly)
	assert.NotEmpty(t, sessCookie.Value)
	require.NotNil(t, stateCookie, "state cookie must be cleared")
	assert.Equal(t, -1, stateCookie.MaxAge)

	require.Len(t, env.rec.events, 2)
	assert.Equal(t, api.AuditAction("user.created"), env.rec.events[0].Action)
	assert.Equal(t, api.AuditAction("auth.oidc.success"), env.rec.events[1].Action)
	assert.Equal(t, "happy@example.com", env.rec.events[1].ActorEmail)
	assert.Equal(t, "allow", env.rec.events[1].Payload["decision"])
}

// JIT disabled + unknown subject: handler emits auth.oidc.failure with
// reason oidc.unknown_subject and 302s to /login?error=unknown_subject.
func TestHandleCallback_UnknownSubject_JITDisabled(t *testing.T) {
	env := newCallbackEnv(t, false, &oidc.Claims{
		Subject: "okta-unknown",
		Email:   "stranger@example.com",
	})
	r := env.callbackRequest(t, "")
	w := httptest.NewRecorder()
	env.handler.HandleCallbackForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(loc, "/login?error="))
	assert.Contains(t, loc, "error=unknown_subject")
	assert.Equal(t, "unknown_subject", resp.Header.Get("X-Edr-Auth-Reason"))
	assert.Equal(t, "403", resp.Header.Get("X-Edr-Auth-Status"))

	require.Len(t, env.rec.events, 1)
	assert.Equal(t, api.AuditAction("auth.oidc.failure"), env.rec.events[0].Action)
	assert.Equal(t, "oidc.unknown_subject", env.rec.events[0].Payload["reason"])
}

// Email collision: a local-password user already owns the email the
// IdP advertises. Handler emits auth.oidc.failure with reason
// oidc.email_conflict and 302s to /login?error=email_conflict.
func TestHandleCallback_EmailCollision(t *testing.T) {
	env := newCallbackEnv(t, true, &oidc.Claims{
		Subject: "okta-collision",
		Email:   "taken@example.com",
	})
	_, err := env.db.ExecContext(t.Context(),
		`INSERT INTO users (email, password_hash, password_salt) VALUES (?, ?, ?)`,
		"taken@example.com", []byte("h"), []byte("s"))
	require.NoError(t, err)

	r := env.callbackRequest(t, "")
	w := httptest.NewRecorder()
	env.handler.HandleCallbackForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "error=email_conflict")
	assert.Equal(t, "409", resp.Header.Get("X-Edr-Auth-Status"))

	require.Len(t, env.rec.events, 1)
	assert.Equal(t, api.AuditAction("auth.oidc.failure"), env.rec.events[0].Action)
	assert.Equal(t, "oidc.email_conflict", env.rec.events[0].Payload["reason"])
}

// Exchange failure: token-endpoint returned an error. Spec puts this
// at 502 (upstream IdP failure) with reason oidc.exchange_failed.
func TestHandleCallback_ExchangeFailureUpstream(t *testing.T) {
	env := newCallbackEnv(t, true, nil)
	env.idp.exchange = errors.New("idp 503 service unavailable")

	r := env.callbackRequest(t, "")
	w := httptest.NewRecorder()
	env.handler.HandleCallbackForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "error=exchange_failed")
	assert.Equal(t, "502", resp.Header.Get("X-Edr-Auth-Status"))

	require.Len(t, env.rec.events, 1)
	assert.Equal(t, api.AuditAction("auth.oidc.callback.error"), env.rec.events[0].Action)
	assert.Equal(t, "error", env.rec.events[0].Payload["decision"])
	assert.Equal(t, "oidc.exchange_failed", env.rec.events[0].Payload["reason"])
}

// HandleLogin sets a state cookie and redirects to the IdP. Pinned
// here to confirm the cookie's flags + the redirect target.
func TestHandleLogin_SetsCookieAndRedirects(t *testing.T) {
	env := newCallbackEnv(t, true, nil)
	r := httptest.NewRequestWithContext(t.Context(), "GET",
		"/api/auth/login?next=/ui/hosts", nil)
	w := httptest.NewRecorder()

	env.handler.HandleLoginForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "https://idp.example.com/authorize")

	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == oidc.StateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)
	assert.True(t, stateCookie.HttpOnly)
	assert.Positive(t, stateCookie.MaxAge)
}

// HandleLogin?reauth=1 forces the IdP to re-prompt for credentials by
// setting prompt=login on the authorize URL. Without it, an IdP that's
// mid-session would silently re-issue a token, defeating the Phase 5
// freshness model. Pin here so a regression in withPromptLogin or in
// handleLogin's branch surfaces immediately.
func TestHandleLogin_ReauthSetsPromptLogin(t *testing.T) {
	env := newCallbackEnv(t, true, nil)
	r := httptest.NewRequestWithContext(t.Context(), "GET",
		"/api/auth/login?reauth=1&next=/ui/hosts", nil)
	w := httptest.NewRecorder()

	env.handler.HandleLoginForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "prompt=login",
		"reauth=1 must append prompt=login to the authorize URL")
}

// HandleLogin without reauth=1 must NOT set prompt=login. Guards a
// regression that always sets it (which would defeat the IdP's own
// session reuse on every login).
func TestHandleLogin_NormalLoginOmitsPromptLogin(t *testing.T) {
	env := newCallbackEnv(t, true, nil)
	r := httptest.NewRequestWithContext(t.Context(), "GET",
		"/api/auth/login?next=/ui/hosts", nil)
	w := httptest.NewRecorder()

	env.handler.HandleLoginForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.NotContains(t, resp.Header.Get("Location"), "prompt=login",
		"normal login must not force prompt=login — the IdP picks its own session policy")
}

// RegisterPublicRoutes mounts both routes against a mux. Pinned to
// catch a regression that splits the prefix or mounts only one.
func TestRegisterPublicRoutes(t *testing.T) {
	env := newCallbackEnv(t, true, nil)
	mux := http.NewServeMux()
	env.handler.RegisterPublicRoutes(mux)

	for _, path := range []string{"/api/auth/login", "/api/auth/callback"} {
		req := httptest.NewRequestWithContext(t.Context(), "GET", path, nil)
		_, pat := mux.Handler(req)
		assert.Equal(t, "GET "+path, pat, "%s must be registered", path)
	}
}
