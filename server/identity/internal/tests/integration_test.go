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
	identitysessions "github.com/fleetdm/edr/server/identity/internal/sessions"
	identityusers "github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/testdb/full"
)

// newIdentity wires identity.bootstrap.New against a fresh test DB, matching what cmd/main does in production. Returns the *Identity
// handle. Tests that need to poke the schema directly call newIdentityWithDB.
func newIdentity(t *testing.T) *bootstrap.Identity {
	id, _ := newIdentityWithDB(t)
	return id
}

// newIdentityWithDB returns the bootstrap.Identity AND the underlying *sqlx.DB for tests that need to seed users directly (the Phase
// 4b SeedAdmin path no longer returns a usable password, so /api/session login tests need a separately-created password user).
func newIdentityWithDB(t *testing.T) (*bootstrap.Identity, *sqlx.DB) {
	t.Helper()
	// testdb/full.Open is the project's standard MySQL fixture for per-context integration tests. It applies every context's schema
	// (including identity's), so the tables exist before store.New runs the alerts FK - which means we don't strictly need to re-run
	// identityCtx.ApplySchema here. We do it anyway to exercise the production code path and assert it is idempotent.
	s := full.Open(t)

	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	id, err := bootstrap.New(t.Context(), bootstrap.Deps{
		DB:                s,
		Logger:            slog.Default(),
		CookieSecure:      false,
		SessionAbsolute:   time.Hour,
		CleanupInterval:   time.Hour, // not exercised by these tests
		SessionSigningKey: signingKey,
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))
	return id, s
}

// TestSeedAdmin_FirstBootCreatesAndIsIdempotent walks the seed-admin path. Phase 4b: SeedAdmin returns a NULL-password break-glass
// row; the redemption URL banner lives in cmd/main, not in seed.Admin. Second call is idempotent on the same DB (returns the same
// row).
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

// TestService_SessionLifecycle exercises the post-Phase-5b session surface (Logout + GetSession + UserExists). Sessions are minted via
// the sessions store directly because Phase 5b retired Service.Login + the POST /api/session HTTP path; production sessions now come
// from the OIDC callback or break-glass FinishLogin/FinishSetup flows, both of which have their own integration tests.
func TestService_SessionLifecycle(t *testing.T) {
	id, db := newIdentityWithDB(t)
	ctx := t.Context()

	usersStore := identityusers.New(db)
	created, err := usersStore.Create(ctx, identityusers.CreateRequest{
		Email: "tester@example.com", Password: "long-enough-password-for-test",
	})
	require.NoError(t, err)

	sessionsStore := identitysessions.New(db, identitysessions.Options{})
	sess, err := sessionsStore.Create(ctx, created.ID,
		identitysessions.CreateOptions{AuthMethod: "oidc"})
	require.NoError(t, err)

	// GetSession round-trips the token.
	got, err := id.Service().GetSession(ctx, sess.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, created.ID, got.UserID)
	assert.Equal(t, sess.CSRFToken, got.CSRFToken)

	// UserExists is happy on a real id, false on a bogus one.
	exists, err := id.Service().UserExists(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, exists)
	exists, err = id.Service().UserExists(ctx, 999999)
	require.NoError(t, err)
	assert.False(t, exists)

	// Logout invalidates the token; subsequent GetSession is
	// ErrSessionNotFound. Logout is idempotent on already-deleted rows.
	require.NoError(t, id.Service().Logout(ctx, sess.ID))
	_, err = id.Service().GetSession(ctx, sess.ID)
	require.ErrorIs(t, err, api.ErrSessionNotFound)
	require.NoError(t, id.Service().Logout(ctx, sess.ID))
}

// TestRegisterRoutes_Authed asserts RegisterAuthedRoutes wires GET /api/session. Calling without a session middleware in front returns
// 500 (the handler logs misconfigured), confirming the route is wired.
func TestRegisterRoutes_Authed(t *testing.T) {
	id := newIdentity(t)
	ctx := t.Context()

	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// GET /api/session without session middleware: handler returns 500 because Session was never pinned to ctx. The 500 itself proves the
	// route is registered (else 404).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/session", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"GET /api/session via RegisterAuthedRoutes (without Session middleware -> 500 misconfigured)")
}

// TestService_LogoutEmptyToken covers the early-return branch in Logout (sessionToken length zero) so a stale or missing cookie cannot
// turn into a Delete query against the DB.
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

// TestService_GetUserNotFound exercises the ErrUserNotFound branch in GetUser. UserExists doesn't reach this branch because it
// short-circuits on userID <= 0; GetUser is the only API path that surfaces the lookup miss.
func TestService_GetUserNotFound(t *testing.T) {
	id := newIdentity(t)
	_, err := id.Service().GetUser(t.Context(), 999_999_999)
	require.ErrorIs(t, err, api.ErrUserNotFound)
}

// TestRun_StopsOnContextCancel verifies the cleanup goroutine returns when ctx is cancelled, and uses a tiny CleanupInterval so the
// ticker fires at least once during the test (covering the cleanup-call branch).
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
