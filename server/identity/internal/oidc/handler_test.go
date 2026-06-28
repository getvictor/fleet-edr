package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
)

// captureAudit collects audit events without writing to MySQL.
type captureAudit struct{ events []api.AuditEvent }

func (c *captureAudit) Record(_ context.Context, e api.AuditEvent) error {
	c.events = append(c.events, e)
	return nil
}

// newTestHandler builds a Handler whose collaborators don't reach DB or the IdP. Tests that walk the failure paths of handleCallback
// (missing/malformed state, state mismatch, missing code) never call Client.Exchange, so a zero-value *Client is safe; tests that DO
// call Exchange would need a real IdP fixture and live in jit_test (DB-backed) instead.
func newTestHandler(t *testing.T) (*Handler, *captureAudit) {
	t.Helper()
	rec := &captureAudit{}
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	h := &Handler{
		resolve:     nil, // never reached: callback failure paths return before client resolution
		provisioner: nil,
		sessions:    nil,
		signingKey:  signingKey,
		stateTTL:    5 * time.Minute,
		audit:       rec,
		logger:      slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	return h, rec
}

// testWriter routes slog output through t.Log so failures show context.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// safeRedirect must drop off-site, scheme-laden, or protocol-relative values and fall back to the default UI landing. Pinned here
// because a regression that lets `next=https://evil.example.com` pass through is a phishing vector.
func TestSafeRedirect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty -> default", "", "/ui/"},
		{"single-slash same-origin path", "/ui/hosts", "/ui/hosts"},
		{"single-slash with query", "/ui/alerts?status=open", "/ui/alerts?status=open"},
		{"protocol-relative // -> default", "//evil.example.com/path", "/ui/"},
		{"https off-site -> default", "https://evil.example.com", "/ui/"},
		{"http off-site -> default", "http://evil.example.com", "/ui/"},
		{"javascript: scheme -> default", "javascript:alert(1)", "/ui/"},
		{"data: scheme -> default", "data:text/html,<script>", "/ui/"},
		{"non-leading slash -> default", "ui/hosts", "/ui/"},
		// Backslash bypass: some browsers normalise "\" to "/" before resolving redirects, so /\evil.com would otherwise be
		// treated as a protocol-relative URL pointing off-origin. Caught by both Gemini and Copilot in PR review; pinned here
		// so a regression can't sneak through.
		{"backslash bypass -> default", "/\\evil.example.com", "/ui/"},
		{"trailing backslash path -> default", "/\\\\evil", "/ui/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, safeRedirect(tc.in))
		})
	}
}

// pathStartsWithSingleSlash distinguishes "/foo" from "//foo" and "/\foo". The double-slash + backslash forms are both protocol-
// relative (some browsers normalise "\" to "/"); rejecting both is the safeRedirect contract.
func TestPathStartsWithSingleSlash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"/", true},
		{"/foo", true},
		{"", false},
		{"foo", false},
		{"//", false},
		{"//evil", false},
		{"/\\", false}, // backslash second char: rejected
		{"/\\evil", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, pathStartsWithSingleSlash(tc.in))
		})
	}
}

// spec:ui-authentication-session/login-attempts-are-rate-limited-and-audited/failed-login-is-audited
//
// Pins the audit-on-failed-login contract on the OIDC code path: a failure during the OIDC callback
// emits an `auth.oidc.failure` audit row carrying the actor email, the typed reason, and the
// user-agent. The spec scenario's "presented email + typed reason" clauses are pinned by the
// ActorEmail and Payload["reason"] assertions below. The "does not include the presented password"
// clause is structurally satisfied because OIDC never presents a password to the EDR (the IdP
// authenticates the user; the EDR sees an OIDC subject claim).
//
// failureAudit emits an auth.oidc.failure row with the spec reason and payload populated; pinned because it's the unknown-subject +
// email-conflict path the operator dashboards key on.
func TestFailureAudit(t *testing.T) {
	t.Parallel()
	h, rec := newTestHandler(t)
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/api/auth/callback?state=x", nil)
	r.Header.Set("User-Agent", "test/1.0")

	h.failureAudit(r, "oidc.unknown_subject", api.AuditEvent{
		Actor:   api.PrincipalRef{Label: "alice@example.com"},
		Payload: map[string]any{"subject": "okta-1"},
	})

	require.Len(t, rec.events, 1)
	got := rec.events[0]
	assert.Equal(t, api.AuditAction("auth.oidc.failure"), got.Action)
	assert.Equal(t, "alice@example.com", got.Actor.Label)
	assert.Equal(t, "deny", got.Payload["decision"])
	assert.Equal(t, "oidc.unknown_subject", got.Payload["reason"])
	assert.Equal(t, "test/1.0", got.Payload["user_agent"])
	assert.Equal(t, "okta-1", got.Payload["subject"])
}

// writeStateCookie + writeSessionCookie each set a cookie with HttpOnly + SameSiteLax + Secure but for different scopes (state cookie
// is path-restricted to /api/auth/; session cookie is /). Pinned because the cookie helpers consolidate three previous inline
// construction sites; a regression that stripped HttpOnly would silently expose the cookie to JS-level XSS. The session-cookie
// attribute set has its own direct test in TestWriteSessionCookie below.
func TestWriteStateCookie(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)
	w := httptest.NewRecorder()
	h.writeStateCookie(w, "VALUE", 60)
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, StateCookieName, c.Name)
	assert.Equal(t, "/api/auth/", c.Path)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, 60, c.MaxAge)
	assert.True(t, c.Secure, "OIDC cookies are unconditionally Secure; localhost browser carve-out keeps dev working")
}

// spec:ui-authentication-session/session-cookie-is-http-only-and-same-site/cookie-attributes-on-login
// spec:ui-authentication-session/sessions-expire-on-idle-and-absolute-timeouts-per-class/cookie-carries-the-absolute-timeout-on-login
//
// Direct unit test for writeSessionCookie's full attribute set. Mirrors TestWriteStateCookie's shape for the OIDC state cookie.
// The session-cookie path is "/" (broader than the state cookie's /api/auth/ scope) because every authed admin endpoint reads it;
// the rest of the attributes (HttpOnly, SameSiteLax, Secure) match the state cookie's hardening. Value is the base64url-encoded
// session token; MaxAge reflects time-until-ExpiresAt in seconds, and Expires equals the session's absolute expiry. The cookie
// scenario is pinned by seeding a representative expiry, then asserting c.MaxAge is positive and c.Expires is within 1s of the
// seeded value (line 199-200). A regression that shortened or lengthened the session window would either trip WithinDuration or
// push MaxAge to zero. Multi-test demonstrator with TestHandleCallback_HappyPath_JITNewUser in callback_integration_test.go (pins
// HttpOnly on the assembled OIDC callback response); this test pins the FULL attribute set in isolation.
func TestWriteSessionCookie(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)
	w := httptest.NewRecorder()

	// Construct a Session literal. writeSessionCookie reads ID + ExpiresAt only; the rest of the fields are irrelevant to the
	// cookie shape. 32 bytes is the canonical session-ID length so the base64url-encoded value is well-formed.
	rawID := make([]byte, 32)
	for i := range rawID {
		rawID[i] = byte(i)
	}
	// A representative absolute expiry (the normal-class 24h cap); writeSessionCookie reads ExpiresAt verbatim, so the exact
	// value only needs to be a positive future instant the assertions below can match against.
	expires := time.Now().Add(24 * time.Hour)
	sess := &sessions.Session{ID: rawID, ExpiresAt: expires}

	h.writeSessionCookie(w, sess)
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, api.SessionCookieName, c.Name)
	assert.Equal(t, api.EncodeToken(rawID), c.Value, "value must be the base64url-encoded session id")
	assert.Equal(t, "/", c.Path, "session cookie scope is the whole app, not /api/auth/")
	assert.True(t, c.HttpOnly, "session cookie must be HttpOnly so JS on any origin cannot read it")
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "SameSiteLax blocks cross-site form-submission auth bypass")
	assert.True(t, c.Secure, "session cookie is unconditionally Secure; localhost dev relies on the browser carve-out")
	assert.Positive(t, c.MaxAge, "MaxAge derived from time-until-ExpiresAt; must be positive for a fresh session")
	assert.WithinDuration(t, expires, c.Expires, time.Second, "Expires reflects ExpiresAt within HTTP-date rounding")
}

// HandleCallback failure paths: state-cookie absent, malformed,
// state-mismatch, code-missing. Each case must
//   - emit one auth.oidc.callback.error audit row
//   - redirect 302 to /login?error=<reason>
//   - clear the state cookie
//   - set the wire-format X-Edr-Auth-Reason header
//
// without ever touching the IdP. These cover the most common
// regression vector: a refactor that bypasses the audit/redirect
// helper for a particular branch and leaks plaintext to the operator.
//
// The "state query param mismatch" case below pins the spec's tampered/stale-state scenario: a state value that does not match
// the server-issued state cookie yields a non-2xx (302 to /login?error=…) without minting a session, and an audit row at
// decision=error with reason oidc.state_mismatch.
// spec:server-identity-authentication/okta-oidc-is-the-primary-login-path/tampered-or-stale-state-is-rejected
func TestHandleCallback_FailurePaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		buildRequest   func(t *testing.T, h *Handler) *http.Request
		expectReason   string
		expectStatusHd string
	}{
		{
			name: "missing state cookie",
			buildRequest: func(t *testing.T, _ *Handler) *http.Request {
				t.Helper()
				return httptest.NewRequestWithContext(t.Context(), "GET", "/api/auth/callback?state=x&code=y", nil)
			},
			expectReason:   "missing_state",
			expectStatusHd: "400",
		},
		{
			name: "malformed state cookie",
			buildRequest: func(t *testing.T, _ *Handler) *http.Request {
				t.Helper()
				r := httptest.NewRequestWithContext(t.Context(), "GET", "/api/auth/callback?state=x&code=y", nil)
				r.AddCookie(&http.Cookie{Name: StateCookieName, Value: "garbage"})
				return r
			},
			expectReason:   "invalid_state",
			expectStatusHd: "400",
		},
		{
			name: "state query param mismatch",
			buildRequest: func(t *testing.T, h *Handler) *http.Request {
				t.Helper()
				cookieVal, err := EncodeStateClaim(h.signingKey, "REAL_STATE", "N", "V", "/ui/", time.Now())
				require.NoError(t, err)
				r := httptest.NewRequestWithContext(t.Context(), "GET",
					"/api/auth/callback?state=ATTACKER_STATE&code=y", nil)
				r.AddCookie(&http.Cookie{Name: StateCookieName, Value: cookieVal})
				return r
			},
			expectReason:   "state_mismatch",
			expectStatusHd: "400",
		},
		{
			name: "missing code (idp returned error)",
			buildRequest: func(t *testing.T, h *Handler) *http.Request {
				t.Helper()
				cookieVal, err := EncodeStateClaim(h.signingKey, "STATE", "N", "V", "/ui/", time.Now())
				require.NoError(t, err)
				r := httptest.NewRequestWithContext(t.Context(), "GET",
					"/api/auth/callback?state=STATE&error=access_denied", nil)
				r.AddCookie(&http.Cookie{Name: StateCookieName, Value: cookieVal})
				return r
			},
			expectReason:   "missing_code",
			expectStatusHd: "400",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, rec := newTestHandler(t)
			r := tc.buildRequest(t, h)
			w := httptest.NewRecorder()

			h.handleCallback(w, r)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusFound, resp.StatusCode, "must redirect, not plaintext error")
			loc := resp.Header.Get("Location")
			assert.Truef(t, strings.HasPrefix(loc, "/login?error="),
				"redirect must land on /login?error=…; got %q", loc)
			assert.Contains(t, loc, "error="+tc.expectReason)
			assert.Equal(t, tc.expectReason, resp.Header.Get("X-Edr-Auth-Reason"))
			assert.Equal(t, tc.expectStatusHd, resp.Header.Get("X-Edr-Auth-Status"))

			// State cookie cleared on every error path.
			var cleared bool
			for _, c := range resp.Cookies() {
				if c.Name == StateCookieName && c.MaxAge < 0 {
					cleared = true
					break
				}
			}
			assert.True(t, cleared, "state cookie must be cleared on error")

			// Exactly one audit row, action=auth.oidc.callback.error.
			require.Len(t, rec.events, 1)
			assert.Equal(t,
				api.AuditAction("auth.oidc.callback.error"),
				rec.events[0].Action)
			assert.Equal(t, "oidc."+tc.expectReason,
				rec.events[0].Payload["reason"])
		})
	}
}
