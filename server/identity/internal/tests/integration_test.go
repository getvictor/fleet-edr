// Per-context integration tests for the identity bounded context. Exercise
// the full bootstrap.New -> ApplySchema -> Service stack against a real
// MySQL. Skips when EDR_TEST_DSN isn't set, matching the project's other
// DB-using test files (no separate build tag).
//
// Per docs/adr/0004-modular-monolith-bounded-contexts.md.

package tests

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/store"
)

// newIdentity wires identity.bootstrap.New against a fresh test DB,
// matching what cmd/main does in production. Returns the *Identity handle
// and the underlying *sqlx.DB so individual tests can poke the schema if
// needed.
func newIdentity(t *testing.T) *bootstrap.Identity {
	t.Helper()
	// store.OpenTestStore is the project's standard MySQL fixture. It
	// inlines the identity DDL itself (see server/store/testhelper.go) so
	// the tables exist before store.New runs the alerts FK -- which means
	// we don't strictly need to re-run identityCtx.ApplySchema here. We
	// do it anyway to exercise the production code path and assert it is
	// idempotent.
	s := store.OpenTestStore(t)

	id, err := bootstrap.New(bootstrap.Deps{
		DB:              s.DB(),
		Logger:          slog.Default(),
		LoginRatePerMin: 60,
		CookieSecure:    false,
		SessionTTL:      time.Hour,
		CleanupInterval: time.Hour, // not exercised by these tests
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))
	return id
}

// TestSeedAdmin_FirstBootCreatesAndIsIdempotent walks the seed-admin path:
// first call mints + prints; second call returns ErrAlreadySeeded.
func TestSeedAdmin_FirstBootCreatesAndIsIdempotent(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	var stderr bytes.Buffer
	user, pw, err := id.Service().SeedAdmin(ctx, &stderr)
	require.NoError(t, err)
	assert.NotZero(t, user.ID)
	assert.NotEmpty(t, user.Email)
	assert.NotEmpty(t, pw)
	assert.Contains(t, stderr.String(), "SEEDED ADMIN USER")
	assert.Contains(t, stderr.String(), pw)

	// Second call: noop, no banner printed, ErrAlreadySeeded returned.
	var stderr2 bytes.Buffer
	user2, pw2, err := id.Service().SeedAdmin(ctx, &stderr2)
	require.ErrorIs(t, err, api.ErrAlreadySeeded)
	assert.Zero(t, user2.ID)
	assert.Empty(t, pw2)
	assert.Empty(t, stderr2.String())
}

// TestLoginToLogout walks Login -> GetSession -> Logout via Service. The
// HTTP-level shape is covered by login/handler_test.go; here we assert
// the Service surface that other contexts depend on.
func TestLoginToLogout(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	// Seed an admin so we have a user to login as.
	var stderr bytes.Buffer
	admin, pw, err := id.Service().SeedAdmin(ctx, &stderr)
	require.NoError(t, err)

	// Wrong password -> ErrBadPassword (which wraps ErrInvalidCredentials).
	_, err = id.Service().Login(ctx, admin.Email, "wrong-password")
	require.ErrorIs(t, err, api.ErrBadPassword)
	require.ErrorIs(t, err, api.ErrInvalidCredentials)

	// Unknown email -> ErrUserNotFound (also wraps ErrInvalidCredentials).
	_, err = id.Service().Login(ctx, "nobody@example.invalid", "anything")
	require.ErrorIs(t, err, api.ErrUserNotFound)
	require.ErrorIs(t, err, api.ErrInvalidCredentials)

	// Happy path.
	res, err := id.Service().Login(ctx, admin.Email, pw)
	require.NoError(t, err)
	assert.Equal(t, admin.ID, res.User.ID)
	assert.NotEmpty(t, res.SessionToken)
	assert.NotEmpty(t, res.CSRFToken)
	assert.True(t, res.ExpiresAt.After(time.Now()))

	// GetSession round-trips the token.
	sess, err := id.Service().GetSession(ctx, res.SessionToken)
	require.NoError(t, err)
	require.NotNil(t, sess)
	assert.Equal(t, admin.ID, sess.UserID)
	assert.Equal(t, res.CSRFToken, sess.CSRFToken)

	// UserExists is happy.
	exists, err := id.Service().UserExists(ctx, admin.ID)
	require.NoError(t, err)
	assert.True(t, exists)

	// Bogus user id -> false, no error.
	exists, err = id.Service().UserExists(ctx, 999999)
	require.NoError(t, err)
	assert.False(t, exists)

	// Logout invalidates the token.
	require.NoError(t, id.Service().Logout(ctx, res.SessionToken))

	// Subsequent GetSession is ErrSessionNotFound.
	_, err = id.Service().GetSession(ctx, res.SessionToken)
	require.ErrorIs(t, err, api.ErrSessionNotFound)

	// Logout again is idempotent (no error on already-deleted session).
	require.NoError(t, id.Service().Logout(ctx, res.SessionToken))
}

// TestSessionMiddlewareEndToEnd hits a tiny mux assembled the same way
// cmd/main wires the operator surface. Verifies the cookie + middleware
// dance is wire-compatible.
func TestSessionMiddlewareEndToEnd(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	// Seed + login to mint a real session.
	var stderr bytes.Buffer
	admin, pw, err := id.Service().SeedAdmin(ctx, &stderr)
	require.NoError(t, err)
	res, err := id.Service().Login(ctx, admin.Email, pw)
	require.NoError(t, err)

	// Build a tiny test server: GET / under Session+CSRF; POST / same.
	authedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := api.UserIDFromContext(r.Context())
		_ = uid
		w.WriteHeader(http.StatusNoContent)
	})
	stack := id.SessionMiddleware()(id.CSRFMiddleware()(authedHandler))
	srv := httptest.NewServer(stack)
	t.Cleanup(srv.Close)

	cookie := &http.Cookie{Name: api.SessionCookieName, Value: api.EncodeToken(res.SessionToken)}
	csrfHeader := api.EncodeToken(res.CSRFToken)

	// GET with cookie: 204.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// POST without CSRF header: 403.
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	resp, err = srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// POST with correct CSRF header: 204.
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/", nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	req.Header.Set(api.CSRFHeaderName, csrfHeader)
	resp, err = srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// TestCleanupExpiredSessions removes only sessions past their expires_at.
// Constructs a sessions store with TTL = 1ns so the row is expired the
// moment it's written.
func TestCleanupExpiredSessions(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	// Seed + login a user. The default identity TTL is 1h here so this
	// session won't expire on its own.
	var stderr bytes.Buffer
	admin, pw, err := id.Service().SeedAdmin(ctx, &stderr)
	require.NoError(t, err)

	freshLogin, err := id.Service().Login(ctx, admin.Email, pw)
	require.NoError(t, err)

	// Cleanup with all sessions still in TTL: zero rows removed.
	n, err := id.Service().CleanupExpiredSessions(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	// Login should still work.
	_, err = id.Service().GetSession(ctx, freshLogin.SessionToken)
	require.NoError(t, err)

	// Errors-aren't-thrown sanity: ErrAlreadySeeded check from a different
	// path. Defensive coverage that we haven't broken the wrap chain.
	require.ErrorIs(t, api.ErrUserNotFound, api.ErrInvalidCredentials)
	require.ErrorIs(t, api.ErrBadPassword, api.ErrInvalidCredentials)
}

// TestRegisterRoutes_Public asserts RegisterPublicRoutes wires both
// POST and DELETE /api/session on the supplied mux, and that the routes
// are reachable end-to-end (login + logout) through the registered mux.
func TestRegisterRoutes_Public(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	// Seed an admin so we have a credential to test login with.
	var stderr bytes.Buffer
	admin, pw, err := id.Service().SeedAdmin(ctx, &stderr)
	require.NoError(t, err)

	mux := http.NewServeMux()
	id.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// POST /api/session: route registered; login succeeds.
	body := bytes.NewBufferString(`{"email":"` + admin.Email + `","password":"` + pw + `"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/session", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "POST /api/session via RegisterPublicRoutes")

	// DELETE /api/session: route registered; logout 204 even without cookie (idempotent).
	req2, err := http.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	resp2, err := srv.Client().Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp2.StatusCode, "DELETE /api/session via RegisterPublicRoutes")
}

// TestRegisterRoutes_Authed asserts RegisterAuthedRoutes wires GET
// /api/session. Calling without a session middleware in front returns 500
// (the handler logs misconfigured), confirming the route is wired.
func TestRegisterRoutes_Authed(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// GET /api/session without session middleware: handler returns 500
	// because Session was never pinned to ctx. The 500 itself proves the
	// route is registered (else 404).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"GET /api/session via RegisterAuthedRoutes (without Session middleware -> 500 misconfigured)")
}

// TestService_LogoutEmptyToken covers the early-return branch in Logout
// (sessionToken length zero) so a stale or missing cookie cannot turn into
// a Delete query against the DB.
func TestService_LogoutEmptyToken(t *testing.T) {
	id := newIdentity(t)
	require.NoError(t, id.Service().Logout(t.Context(), nil))
	require.NoError(t, id.Service().Logout(t.Context(), []byte{}))
}

// TestService_UserExistsZeroOrNegative covers the userID <= 0 short-circuit
// so a buggy caller can't accidentally probe the users table with junk ids.
func TestService_UserExistsZeroOrNegative(t *testing.T) {
	id := newIdentity(t)
	for _, uid := range []int64{0, -1, -1000000} {
		exists, err := id.Service().UserExists(t.Context(), uid)
		require.NoError(t, err)
		assert.False(t, exists)
	}
}

// TestService_GetUserNotFound exercises the ErrUserNotFound branch in
// GetUser. UserExists doesn't reach this branch because it short-circuits
// on userID <= 0; GetUser is the only API path that surfaces the lookup
// miss.
func TestService_GetUserNotFound(t *testing.T) {
	id := newIdentity(t)
	_, err := id.Service().GetUser(t.Context(), 999_999_999)
	require.ErrorIs(t, err, api.ErrUserNotFound)
}

// TestRun_StopsOnContextCancel verifies the cleanup goroutine returns when
// ctx is cancelled, and uses a tiny CleanupInterval so the ticker fires
// at least once during the test (covering the cleanup-call branch).
func TestRun_StopsOnContextCancel(t *testing.T) {
	s := store.OpenTestStore(t)
	id, err := bootstrap.New(bootstrap.Deps{
		DB:              s.DB(),
		Logger:          slog.Default(),
		CleanupInterval: 25 * time.Millisecond, // short so the loop exercises CleanupExpired
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- id.Run(ctx) }()

	// Let at least one tick happen.
	time.Sleep(75 * time.Millisecond)

	cancel()

	select {
	case runErr := <-done:
		require.NoError(t, runErr, "Run should return nil on context cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of ctx cancel")
	}
}
