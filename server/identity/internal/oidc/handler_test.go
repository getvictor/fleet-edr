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
)

// captureAudit collects audit events without writing to MySQL.
type captureAudit struct{ events []api.AuditEvent }

func (c *captureAudit) Record(_ context.Context, e api.AuditEvent) error {
	c.events = append(c.events, e)
	return nil
}

// newTestHandler builds a Handler whose collaborators don't reach DB
// or the IdP. Tests that walk the failure paths of handleCallback
// (missing/malformed state, state mismatch, missing code) never call
// Client.Exchange, so a zero-value *Client is safe; tests that DO
// call Exchange would need a real IdP fixture and live in jit_test
// (DB-backed) instead.
func newTestHandler(t *testing.T) (*Handler, *captureAudit) {
	t.Helper()
	rec := &captureAudit{}
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	h := &Handler{
		client:      nil, // never reached on failure paths
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

// safeRedirect must drop off-site, scheme-laden, or protocol-relative
// values and fall back to the default UI landing. Pinned here because
// a regression that lets `next=https://evil.example.com` pass through
// is a phishing vector.
func TestSafeRedirect(t *testing.T) {
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
		// Backslash bypass: some browsers normalise "\" to "/" before
		// resolving redirects, so /\evil.com would otherwise be treated
		// as a protocol-relative URL pointing off-origin. Caught by both
		// Gemini and Copilot in PR review; pinned here so a regression
		// can't sneak through.
		{"backslash bypass -> default", "/\\evil.example.com", "/ui/"},
		{"trailing backslash path -> default", "/\\\\evil", "/ui/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, safeRedirect(tc.in))
		})
	}
}

// pathStartsWithSingleSlash distinguishes "/foo" from "//foo" and
// "/\foo". The double-slash + backslash forms are both protocol-
// relative (some browsers normalise "\" to "/"); rejecting both is
// the safeRedirect contract.
func TestPathStartsWithSingleSlash(t *testing.T) {
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
			assert.Equal(t, tc.want, pathStartsWithSingleSlash(tc.in))
		})
	}
}

// failureAudit emits an auth.oidc.failure row with the spec reason and
// payload populated; pinned because it's the unknown-subject + email-
// conflict path the operator dashboards key on.
func TestFailureAudit(t *testing.T) {
	h, rec := newTestHandler(t)
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/api/auth/callback?state=x", nil)
	r.Header.Set("User-Agent", "test/1.0")

	h.failureAudit(r, "oidc.unknown_subject", api.AuditEvent{
		ActorEmail: "alice@example.com",
		Payload:    map[string]any{"subject": "okta-1"},
	})

	require.Len(t, rec.events, 1)
	got := rec.events[0]
	assert.Equal(t, api.AuditAction("auth.oidc.failure"), got.Action)
	assert.Equal(t, "alice@example.com", got.ActorEmail)
	assert.Equal(t, "deny", got.Payload["decision"])
	assert.Equal(t, "oidc.unknown_subject", got.Payload["reason"])
	assert.Equal(t, "test/1.0", got.Payload["user_agent"])
	assert.Equal(t, "okta-1", got.Payload["subject"])
}

// writeStateCookie + writeSessionCookie set a single audited cookie
// with HttpOnly + SameSiteLax + the path scope expected by the
// handler. Pinned because the cookie helpers consolidate three
// previous inline construction sites; a regression that stripped
// HttpOnly would silently expose state to JS-level XSS.
func TestWriteStateCookie(t *testing.T) {
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
func TestHandleCallback_FailurePaths(t *testing.T) {
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
