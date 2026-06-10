package seed_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

func newSeedFixture(t *testing.T) (*users.Store, *rbac.Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return users.New(db), rbac.New(db), db
}

// spec:ui-authentication-session/initial-operator-account-is-bootstrapped-at-first-startup/first-startup-seed
// spec:ui-authentication-session/initial-operator-account-is-bootstrapped-at-first-startup/recovery-after-a-lost-password
//
// SeedsOnEmptyTable: admin row inserted with NULL password + is_breakglass=1, AND a super_admin role binding lands in role_bindings.
// The flow does NOT print a password banner: the redemption URL banner lives in cmd/main.
//
// The spec was rewritten in PR #267 to describe the break-glass admin + redemption-URL flow (issue #257). Both
// scenarios this test pins reduce to the same structural property: "if the users table is empty when the seeder runs,
// a break-glass admin row is inserted with the well-known email + NULL password + is_breakglass=1 + super_admin binding,
// and the seed function itself does NOT write a password banner". For first-startup-seed the precondition is "fresh
// install with empty users table"; for recovery-after-a-lost-password the precondition is "operator deleted the user row
// and restarted" (which leaves the table empty from the seeder's perspective). The cmd/main redemption-URL emission is
// covered separately at startup-banner integration and is out of scope here; this test pins the seed function's contract
// directly via the stderr buffer being empty.
func TestAdmin_SeedsOnEmptyTable(t *testing.T) {
	t.Parallel()
	us, rb, db := newSeedFixture(t)
	var stderr bytes.Buffer

	u, pw, err := seed.Admin(t.Context(), us, rb, slog.Default(), &stderr)
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, seed.DefaultAdminEmail, u.Email)
	assert.True(t, u.IsBreakglass, "seeded admin must be break-glass")
	assert.Empty(t, pw, "Admin returns no password (banner is emitted by cmd/main)")
	assert.Empty(t, stderr.String(), "banner is emitted by cmd/main, not by seed")

	// Verify the super_admin binding is present so the chokepoint grants the admin every action on first login. Without this, /api/hosts
	// and every other privileged route 403s with no_matching_rule (the bug QA surfaced).
	bindings, err := rb.ListLiveBindings(t.Context(), u.ID)
	require.NoError(t, err)
	require.Len(t, bindings, 1, "seeded admin must have exactly one role binding")
	assert.Equal(t, seed.DefaultAdminRole, bindings[0].RoleID)
	assert.Equal(t, "global", string(bindings[0].ScopeType))
	assert.Equal(t, "*", bindings[0].ScopeID)
	_ = db
}

// spec:ui-authentication-session/initial-operator-account-is-bootstrapped-at-first-startup/restart-with-an-existing-operator
//
// Pins the no-duplicate-account-on-rerun clause: a second seed against a populated DB returns the same
// row instead of inserting another, AND the rbac binding count stays at 1 (no banner check needed
// since banner emission lives in cmd/main, but the "no banner is emitted" clause is
// structural here: the seed function never writes to stderr on a no-op path).
//
// Idempotent: a second seed against the same DB returns the existing row instead of attempting another insert AND does not duplicate
// the role binding (rbac unique key swallows the conflict). Pinned because container restarts re-run the seed step.
func TestAdmin_IdempotentOnRerun(t *testing.T) {
	t.Parallel()
	us, rb, _ := newSeedFixture(t)
	first, _, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, _, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, first.ID, second.ID, "second seed must return the same row")

	// Still exactly one binding: the duplicate-entry on the rbac
	// unique key was swallowed.
	bindings, err := rb.ListLiveBindings(t.Context(), second.ID)
	require.NoError(t, err)
	assert.Len(t, bindings, 1, "re-seed must not duplicate the role binding")
}

// SelfHealsMissingBinding: a deployment that lost the role binding (manual SQL surgery, partially-restored backup) gets the binding
// back on the next seed call. Pinned because this is the recovery path the bug-fix that introduced bind-on-seed unblocks.
func TestAdmin_SelfHealsMissingRoleBinding(t *testing.T) {
	t.Parallel()
	us, rb, db := newSeedFixture(t)
	first, _, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, first)

	// Wipe the binding to simulate the broken-state QA surfaced.
	_, err = db.ExecContext(t.Context(),
		`DELETE FROM role_bindings WHERE user_id = ?`, first.ID)
	require.NoError(t, err)

	// Re-seed. The binding should come back.
	_, _, err = seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	bindings, err := rb.ListLiveBindings(t.Context(), first.ID)
	require.NoError(t, err)
	require.Len(t, bindings, 1, "lost binding must self-heal on next seed")
	assert.Equal(t, seed.DefaultAdminRole, bindings[0].RoleID)
}

// Pre-existing unrelated users in the table do NOT block the seed: the canonical break-glass admin is created alongside them. Pinned
// to prevent a regression that returns the table-non-empty short circuit (the wave-0 carve-out, removed pre-pilot because there is no
// wave-0 deployment to migrate from).
func TestAdmin_SeedsAlongsideUnrelatedUsers(t *testing.T) {
	t.Parallel()
	us, rb, _ := newSeedFixture(t)
	_, err := us.Create(t.Context(), users.CreateRequest{
		Email: "first@example.com", Password: "this-is-a-long-pw",
	})
	require.NoError(t, err)

	u, _, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, seed.DefaultAdminEmail, u.Email)
	assert.True(t, u.IsBreakglass)
}

func TestAdmin_NilStoreErrors(t *testing.T) {
	t.Parallel()
	_, _, err := seed.Admin(t.Context(), nil, nil, slog.Default(), nil)
	require.Error(t, err)
}

func TestAdmin_NilRBACErrors(t *testing.T) {
	t.Parallel()
	us, _, _ := newSeedFixture(t)
	_, _, err := seed.Admin(t.Context(), us, nil, slog.Default(), nil)
	require.Error(t, err)
}

// Defensive guard: a non-breakglass row at the canonical admin email is an unexpected state (no pre-pilot deployment produces it).
// Admin SHOULD fail loud rather than silently rewrite the row.
func TestAdmin_CanonicalEmailNonBreakglassErrors(t *testing.T) {
	t.Parallel()
	us, rb, _ := newSeedFixture(t)
	_, err := us.Create(t.Context(), users.CreateRequest{
		Email: seed.DefaultAdminEmail, Password: "this-is-a-long-pw",
	})
	require.NoError(t, err)

	_, _, err = seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.Error(t, err, "non-breakglass row at canonical email must error, not silently skip")
	assert.Contains(t, err.Error(), "is_breakglass=0")
}

// DB-error path: when GetByEmail returns a non-NotFound error (here: the underlying *sqlx.DB is closed before the call), Admin
// surfaces the error wrapped under "look up existing admin" instead of treating it as "user does not exist" and falling through to
// CreateBreakglass. Pinned because the silent-fall-through was the pre-cleanup behaviour; a regression would mean a DB outage gets
// papered over as "fresh DB, seed away".
func TestAdmin_GetByEmailErrorPropagates(t *testing.T) {
	t.Parallel()
	us, rb, db := newSeedFixture(t)
	require.NoError(t, db.Close(), "force GetByEmail into a real error path")

	_, _, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "look up existing admin")
}

// Nil logger falls back to slog.Default(). Pinned so a caller that forgets to pass a logger does not nil-deref the WarnContext /
// InfoContext calls inside the seed flow.
func TestAdmin_NilLoggerUsesDefault(t *testing.T) {
	t.Parallel()
	us, rb, _ := newSeedFixture(t)
	u, _, err := seed.Admin(t.Context(), us, rb, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, u)
}
