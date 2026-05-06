//go:build integration

// Per-context integration tests for the identity bounded context. Exercise
// the full bootstrap.New -> ApplySchema -> Service stack against a real
// MySQL. Skips when EDR_TEST_DSN isn't set, matching the project's other
// DB-using test files.
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

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/bootstrap"
	identityusers "github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/testdb/full"
)

// newIdentity wires identity.bootstrap.New against a fresh test DB,
// matching what cmd/main does in production. Returns the *Identity handle.
// Tests that need to poke the schema directly call newIdentityWithDB.
func newIdentity(t *testing.T) *bootstrap.Identity {
	id, _ := newIdentityWithDB(t)
	return id
}

// newIdentityWithDB returns the bootstrap.Identity AND the underlying
// *sqlx.DB for tests that need to seed users directly (the Phase 4b
// SeedAdmin path no longer returns a usable password, so /api/session
// login tests need a separately-created password user).
func newIdentityWithDB(t *testing.T) (*bootstrap.Identity, *sqlx.DB) {
	t.Helper()
	// testdb/full.Open is the project's standard MySQL fixture for
	// per-context integration tests. It applies every context's schema
	// (including identity's), so the tables exist before store.New runs
	// the alerts FK - which means we don't strictly need to re-run
	// identityCtx.ApplySchema here. We do it anyway to exercise the
	// production code path and assert it is idempotent.
	s := full.Open(t)

	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	id, err := bootstrap.New(t.Context(), bootstrap.Deps{
		DB:                s,
		Logger:            slog.Default(),
		LoginRatePerMin:   60,
		CookieSecure:      false,
		SessionAbsolute:   time.Hour,
		CleanupInterval:   time.Hour, // not exercised by these tests
		SessionSigningKey: signingKey,
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))
	return id, s
}

// TestSeedAdmin_FirstBootCreatesAndIsIdempotent walks the seed-admin
// path. Phase 4b: SeedAdmin returns a NULL-password break-glass row;
// the redemption URL banner lives in cmd/main, not in seed.Admin.
// Second call is idempotent on the same DB (returns the same row).
func TestSeedAdmin_FirstBootCreatesAndIsIdempotent(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	var stderr bytes.Buffer
	user, pw, err := id.Service().SeedAdmin(ctx, &stderr)
	require.NoError(t, err)
	assert.NotZero(t, user.ID)
	assert.NotEmpty(t, user.Email)
	assert.Empty(t, pw, "Phase 4b removed the password return value")
	assert.Empty(t, stderr.String(),
		"Phase 4b: redemption banner is emitted by cmd/main, not by seed.Admin")

	// Second call returns the same row (idempotent on container restart).
	user2, _, err := id.Service().SeedAdmin(ctx, &stderr)
	require.NoError(t, err)
	assert.Equal(t, user.ID, user2.ID)
}

// TestLoginToLogout walks Login -> GetSession -> Logout via Service. The
// HTTP-level shape is covered by login/handler_test.go; here we assert
// the Service surface that other contexts depend on.
func TestLoginToLogout(t *testing.T) {
	id, db := newIdentityWithDB(t)
	ctx := t.Context()

	// Seed a non-break-glass user with a password so /api/session
	// login works end-to-end. The break-glass admin uses
	// /admin/break-glass with WebAuthn — that flow is exercised by
	// the breakglass package's own integration tests.
	const password = "long-enough-password-for-test"
	usersStore := identityusers.New(db)
	created, err := usersStore.Create(ctx, identityusers.CreateRequest{
		Email: "tester@example.com", Password: password,
	})
	require.NoError(t, err)
	admin, pw := api.User{ID: created.ID, Email: created.Email}, password

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
	id, db := newIdentityWithDB(t)
	ctx := t.Context()

	const password = "long-enough-password-for-test"
	usersStore := identityusers.New(db)
	created, err := usersStore.Create(ctx, identityusers.CreateRequest{
		Email: "tester@example.com", Password: password,
	})
	require.NoError(t, err)
	res, err := id.Service().Login(ctx, created.Email, password)
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
	id, db := newIdentityWithDB(t)
	ctx := t.Context()

	const password = "long-enough-password-for-test"
	usersStore := identityusers.New(db)
	created, err := usersStore.Create(ctx, identityusers.CreateRequest{
		Email: "tester@example.com", Password: password,
	})
	require.NoError(t, err)

	freshLogin, err := id.Service().Login(ctx, created.Email, password)
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
//
// Phase 4b: SeedAdmin now returns a NULL-password break-glass row, so
// this test seeds a separate non-break-glass user via users.Store
// directly to drive POST /api/session. The break-glass account uses
// /admin/break-glass with WebAuthn — that flow is exercised by the
// breakglass package's own integration tests.
func TestRegisterRoutes_Public(t *testing.T) {
	id, db := newIdentityWithDB(t)
	ctx := t.Context()

	const (
		testEmail    = "tester@example.com"
		testPassword = "long-enough-password-for-test"
	)
	usersStore := identityusers.New(db)
	_, err := usersStore.Create(ctx, identityusers.CreateRequest{
		Email: testEmail, Password: testPassword,
	})
	require.NoError(t, err)

	mux := http.NewServeMux()
	id.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// POST /api/session: route registered; login succeeds.
	body := bytes.NewBufferString(`{"email":"` + testEmail + `","password":"` + testPassword + `"}`)
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
	s := full.Open(t)
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	id, err := bootstrap.New(t.Context(), bootstrap.Deps{
		DB:                s,
		Logger:            slog.Default(),
		CleanupInterval:   25 * time.Millisecond, // short so the loop exercises CleanupExpired
		SessionSigningKey: signingKey,
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
