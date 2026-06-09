// Package testkit is identity's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full,
// test/integration) reaches for bootstrap. The two contracts are
// deliberately separate: bootstrap is for standing up real wiring;
// testkit is for tests that need just enough of identity to exercise
// some other piece (the users table, a stub User existence check, etc.)
// without spinning up the full Identity service.
//
// Today the package only exposes ApplySchema. As cross-context tests
// grow, this is the right home for identity-specific seeders
// (e.g. SeedUser) and fakes (e.g. UserExistsAlways) so each test file
// stops re-implementing them.
//
// Constraint: this package must NOT import any other bounded context.
// arch-go pins the rule. Cross-context fixture composition is
// server/testdb/full's job, not testkit's.
package testkit

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
)

// ApplySchema runs identity's DDL + idempotent ALTERs against db. Thin wrapper over bootstrap.ApplySchema so the test surface is
// importable separately from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}

// AllowAllAuthZ implements api.AuthZ as an unconditional grant. Used by tests that need a chokepoint dependency satisfied but are
// not exercising the role matrix; the real engine's per-action behaviour is covered exhaustively in the authz package's own tests,
// so making every cross-context test compile + recompile a Rego bundle is avoidable overhead.
type AllowAllAuthZ struct{}

// Allow satisfies api.AuthZ; always returns Decision{Allow: true,
// Reason: "granted"}.
func (AllowAllAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: true, Reason: "granted"}, nil
}

// DenyAuthZ implements api.AuthZ with a fixed deny reason. Used by handler tests that exercise the deny-path response shape (403 +
// X-Edr-Authz-Reason header) without depending on the live policy.
type DenyAuthZ struct {
	Reason string
}

// Allow satisfies api.AuthZ; returns Decision{Allow: false} with the configured reason. Default reason "no_matching_rule" matches the
// production policy's deny label so tests that pin the header value stay in sync with the live decision shape.
func (d DenyAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	r := d.Reason
	if r == "" {
		r = "no_matching_rule"
	}
	return api.Decision{Allow: false, Reason: r}, nil
}

// SeededUser is the result of SeedJITUser: the user row + a live session ready to drop into a cookie. ID is the user's primary key;
// SessionCookie is the base64url-encoded session token (use this for the `edr_session` cookie value); CSRFToken is the per-session
// CSRF secret base64url-encoded for the `X-Csrf-Token` header.
type SeededUser struct {
	ID            int64
	Email         string
	Role          string
	SessionCookie string
	CSRFToken     string
}

// SeedJITUser inserts the rows an OIDC JIT-provisioned operator would
// land in: users + identities (provider='oidc', subject="oidc:<email>"
// to mimic an IdP-stable subject distinct from the email column) +
// role_bindings (deployment-wide scope, no expiry) + a fresh session.
// Returns the user id + the cookie/CSRF pair the test plugs into HTTP
// requests against the protected mux.
//
// Cross-context tests use this to skip the full OIDC dance - the OIDC
// callback flow is exhaustively covered in the oidc package's own
// tests, and a cross-context test re-running the parsing dance would
// just be re-testing OIDC. The end-state SQL shape and the live
// session cookie are what every downstream chokepoint check actually
// reads, so this helper matches that shape exactly.
//
// The synthetic "oidc:<email>" subject keeps the helper deterministic
// (same email -> same identity row on re-seed) while still distinct
// from the email column the way a real IdP-issued `sub` claim is.
// Tests that need a specific subject string can drop the helper and
// INSERT the row by hand.
//
// auth_method is hardcoded to "oidc" because that's the JIT-provisioned
// path's session class (break-glass goes through a distinct flow with
// its own helper). last_auth_at is set to NOW() by sessions.Store so
// the chokepoint's freshness gate (reauth window) returns true for
// destructive actions; tests that need a stale session age the row
// directly.
func SeedJITUser(t *testing.T, db *sqlx.DB, email, role string) SeededUser {
	t.Helper()
	ctx := t.Context()

	userRes, err := db.ExecContext(ctx,
		`INSERT INTO users (email, status) VALUES (?, 'active')`,
		email)
	require.NoErrorf(t, err, "seed user %q", email)
	userID, err := userRes.LastInsertId()
	require.NoError(t, err)

	subject := "oidc:" + email
	identityRes, err := db.ExecContext(ctx,
		`INSERT INTO identities (user_id, provider, subject) VALUES (?, 'oidc', ?)`,
		userID, subject)
	require.NoErrorf(t, err, "seed identity for %q", email)
	identityID, err := identityRes.LastInsertId()
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id)
		 VALUES (?, ?, 'global', '*')`,
		userID, role)
	require.NoErrorf(t, err, "seed role binding %s for user %d", role, userID)

	sessionStore := sessions.New(db, sessions.Options{})
	sess, err := sessionStore.Create(ctx, userID, sessions.CreateOptions{
		IdentityID: &identityID,
		AuthMethod: "oidc",
	})
	require.NoError(t, err, "mint session")

	return SeededUser{
		ID:            userID,
		Email:         email,
		Role:          role,
		SessionCookie: api.EncodeToken(sess.ID),
		CSRFToken:     api.EncodeToken(sess.CSRFToken),
	}
}

// AgeSession backdates a seeded session's last_auth_at column so the
// chokepoint's freshness gate (reauth window) returns false. Used to
// verify that a destructive action that would normally be granted
// denies with reauth_required when the session is stale.
//
// The interval uses MICROSECOND granularity so callers can age the
// session by any duration the sessions table's TIMESTAMP(6) column
// can represent, including sub-second offsets near the reauth-window
// boundary. age.Microseconds() preserves the full precision Go's
// time.Duration carries.
func AgeSession(t *testing.T, db *sqlx.DB, userID int64, age time.Duration) {
	t.Helper()
	ctx := t.Context()
	_, err := db.ExecContext(ctx,
		`UPDATE sessions SET last_auth_at = NOW(6) - INTERVAL ? MICROSECOND WHERE user_id = ?`,
		age.Microseconds(), userID)
	require.NoErrorf(t, err, "age session for user %d", userID)
}
