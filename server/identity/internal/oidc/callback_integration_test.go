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

// fakeIDPClient is the test seam for *oidc.Client. Production code uses the real go-oidc-backed client; tests inject a deterministic
// stub so the callback's happy path can be walked without spinning up discovery + signing keys.
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
	prov := oidc.NewProvisioner(db, usersStore, identitiesStore, rbacStore, rec, oidc.ProvisionerOptions{})

	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	idp := &fakeIDPClient{claims: claims}
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	h := oidc.NewHandlerForTest(idp, oidc.Policy{AllowJIT: jitEnabled}, prov, sessionsStore, signingKey, rec, logger)
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

// spec:ui-authentication-session/session-cookie-is-http-only-and-same-site/cookie-attributes-on-login
// spec:ui-authentication-session/login-mints-a-session-cookie-and-a-csrf-token/successful-login
// spec:server-identity-authentication/okta-oidc-is-the-primary-login-path/successful-callback-mints-a-session
// spec:server-identity-audit-log/authentication-outcomes-write-an-audit-row/successful-sso-login-is-audited-with-the-user-principal
//
// Pins the cookie-attributes clause AND the spec's "successful login" scenario on the OIDC happy-path session mint:
// after the callback succeeds and a session is created, the response is 302 to the state's pinned redirect (/ui/) and
// sets the session cookie with HttpOnly=true. The assertion on sessCookie.HttpOnly below pins one clause; the full
// attribute set (Path=/, SameSiteLax, Secure, MaxAge derived from ExpiresAt) is pinned in isolation by
// TestWriteSessionCookie in handler_test.go, which calls writeSessionCookie directly with a constructed Session literal.
// The 302 status + Location: /ui/ assertion + the audit.oidc.success row together pin the spec's "successful login"
// scenario for the OIDC entry point; the break-glass entry point's happy path is pinned separately by
// TestHandle_FullLogin_Success in server/identity/internal/breakglass/finishflow_test.go. Multi-test
// demonstrator: this end-to-end test catches a regression where the handler stops calling
// writeSessionCookie at all; the unit test catches a regression inside the helper itself.
//
// Happy path: state cookie verifies, code exchanges, JIT runs (subject is fresh, JIT enabled), session minted, response is a 302 to
// the state's pinned redirect with both cookies set. Audits one auth.oidc.success row plus one user.created row from the provisioner.
func TestHandleCallback_HappyPath_JITNewUser(t *testing.T) {
	t.Parallel()
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
	assert.Equal(t, "happy@example.com", env.rec.events[1].Actor.Label)
	assert.Equal(t, "allow", env.rec.events[1].Payload["decision"])
}

// JIT disabled + unknown subject: handler emits auth.oidc.failure with
// reason oidc.unknown_subject and 302s to /login?error=unknown_subject.
// spec:server-identity-authentication/just-in-time-provisioning-of-unknown-sso-users/unknown-subject-is-rejected-when-jit-is-disabled
func TestHandleCallback_UnknownSubject_JITDisabled(t *testing.T) {
	t.Parallel()
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

// Email collision: a local-password user already owns the email the IdP advertises. Handler emits auth.oidc.failure with reason
// oidc.email_conflict and 302s to /login?error=email_conflict.
func TestHandleCallback_EmailCollision(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// HandleLogin?reauth=1 forces the IdP to re-prompt for credentials by setting prompt=login on the authorize URL. Without it,
// an IdP that's mid-session would silently re-issue a token, defeating the reauth freshness model. Pin here so a regression in
// withPromptLogin or in handleLogin's branch surfaces immediately.
func TestHandleLogin_ReauthSetsPromptLogin(t *testing.T) {
	t.Parallel()
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

// HandleLogin without reauth=1 must NOT set prompt=login. Guards a regression that always sets it (which would defeat the IdP's own
// session reuse on every login).
func TestHandleLogin_NormalLoginOmitsPromptLogin(t *testing.T) {
	t.Parallel()
	env := newCallbackEnv(t, true, nil)
	r := httptest.NewRequestWithContext(t.Context(), "GET",
		"/api/auth/login?next=/ui/hosts", nil)
	w := httptest.NewRecorder()

	env.handler.HandleLoginForTest()(w, r)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.NotContains(t, resp.Header.Get("Location"), "prompt=login",
		"normal login must not force prompt=login: the IdP picks its own session policy")
}

// RegisterPublicRoutes mounts both routes against a mux. Pinned to
// catch a regression that splits the prefix or mounts only one.
func TestRegisterPublicRoutes(t *testing.T) {
	t.Parallel()
	env := newCallbackEnv(t, true, nil)
	mux := http.NewServeMux()
	env.handler.RegisterPublicRoutes(mux)

	for _, path := range []string{"/api/auth/login", "/api/auth/callback"} {
		req := httptest.NewRequestWithContext(t.Context(), "GET", path, nil)
		_, pat := mux.Handler(req)
		assert.Equal(t, "GET "+path, pat, "%s must be registered", path)
	}
}

// --- the sign-in policy is bound to the configuration that verified the token (issue #1044) ---

// mutatingIDPClient flips the deployment's stored configuration during the token exchange, which is the window an admin's save lands
// in: the code has been sent to the provider and the claims have not yet been judged.
type mutatingIDPClient struct {
	claims     *oidc.Claims
	onExchange func()
}

func (m *mutatingIDPClient) AuthURL(state, _, _ string) string {
	return "https://idp.example.com/authorize?state=" + state
}

func (m *mutatingIDPClient) Exchange(context.Context, string, string, string) (*oidc.Claims, error) {
	m.onExchange()
	return m.claims, nil
}

// A sign-in is judged under the configuration that verified its token, not the one stored by the time its claims are read.
//
// The callback resolves a provider client and then judges the claims it gets back. Those were two reads of the stored configuration,
// so an admin saving during the exchange had the token verified under one and its group mapping applied from the next. Reaching it
// needs an account at the outgoing provider whose sign-in completes inside the admin's save; this holds that window open on purpose.
//
// The assertion is the role actually bound to the user, which is the thing an operator would see and which the handler does not
// compute: under the old configuration alice is an admin, under the new one her group means nothing.
//
// spec:sso-configuration/a-sign-in-is-judged-under-one-configuration/a-save-during-the-exchange-does-not-change-this-sign-in
func TestHandleCallback_policyIsBoundToTheConfigurationThatVerifiedTheToken(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	rec := &recAudit{}
	prov := oidc.NewProvisioner(db, users.New(db), identities.New(db), rbac.New(db), rec, oidc.ProvisionerOptions{})

	// The stored configuration, as both reads of the callback see it. Starts mapping edr-admins to admin.
	stored := oidc.Policy{
		AllowJIT: true, DefaultRole: "analyst", GroupsClaim: "groups",
		GroupRoles: map[string]string{"edr-admins": "admin"},
	}
	claims := &oidc.Claims{Subject: "okta-alice", Email: "alice@example.com", Raw: map[string]any{"groups": []any{"edr-admins"}}}
	idp := &mutatingIDPClient{claims: claims, onExchange: func() {
		// The admin saves: the mapping is gone, so under this configuration alice's group means nothing.
		stored = oidc.Policy{AllowJIT: true, DefaultRole: "analyst"}
	}}

	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	// Both the client and the policy come from one read, exactly as production's resolver returns them.
	h := oidc.NewHandlerForTestWithResolve(func(context.Context) (oidc.IDPClient, oidc.Policy, error) {
		return idp, stored, nil
	}, prov, sessions.New(db, sessions.Options{}), signingKey, rec, logger)

	env := &callbackTestEnv{db: db, handler: h, rec: rec, signingKey: signingKey, now: time.Now()}
	w := httptest.NewRecorder()
	h.HandleCallbackForTest()(w, env.callbackRequest(t, ""))
	require.Equal(t, http.StatusFound, w.Code, "the sign-in itself must succeed")

	var roles []string
	require.NoError(t, db.SelectContext(t.Context(), &roles,
		`SELECT rb.role_id FROM role_bindings rb JOIN users u ON u.id = rb.user_id WHERE u.email = ?`, "alice@example.com"))
	assert.Equal(t, []string{"admin"}, roles,
		"alice signed in under the configuration that mapped her group; the save that landed mid-exchange applies to the next sign-in")
}
