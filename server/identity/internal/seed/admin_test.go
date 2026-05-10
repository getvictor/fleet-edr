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

// SeedsOnEmptyTable: admin row inserted with NULL password +
// is_breakglass=1, AND a super_admin role binding lands in
// role_bindings. The Phase 4b flow does NOT print a password
// banner - the redemption URL banner lives in cmd/main.
func TestAdmin_SeedsOnEmptyTable(t *testing.T) {
	us, rb, db := newSeedFixture(t)
	var stderr bytes.Buffer

	u, pw, err := seed.Admin(t.Context(), us, rb, slog.Default(), &stderr)
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, seed.DefaultAdminEmail, u.Email)
	assert.True(t, u.IsBreakglass, "Phase 4b admin must be break-glass")
	assert.Empty(t, pw, "Phase 4b removed the password return value")
	assert.Empty(t, stderr.String(), "Phase 4b: banner is emitted by cmd/main, not by seed")

	// Verify the super_admin binding is present so the chokepoint
	// grants the admin every action on first login. Without this,
	// /api/hosts and every other privileged route 403s with
	// no_matching_rule (the bug QA surfaced).
	bindings, err := rb.ListLiveBindings(t.Context(), u.ID)
	require.NoError(t, err)
	require.Len(t, bindings, 1, "seeded admin must have exactly one role binding")
	assert.Equal(t, seed.DefaultAdminRole, bindings[0].RoleID)
	assert.Equal(t, "tenant", string(bindings[0].ScopeType))
	assert.Equal(t, "*", bindings[0].ScopeID)
	_ = db
}

// Idempotent: a second seed against the same DB returns the existing
// row instead of attempting another insert AND does not duplicate
// the role binding (rbac unique key swallows the conflict). Pinned
// because container restarts re-run the seed step.
func TestAdmin_IdempotentOnRerun(t *testing.T) {
	us, rb, _ := newSeedFixture(t)
	first, _, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, _, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, first.ID, second.ID, "second seed must return the same row")

	// Still exactly one binding - the duplicate-entry on the rbac
	// unique key was swallowed.
	bindings, err := rb.ListLiveBindings(t.Context(), second.ID)
	require.NoError(t, err)
	assert.Len(t, bindings, 1, "re-seed must not duplicate the role binding")
}

// SelfHealsMissingBinding: a deployment that lost the role binding
// (manual SQL surgery, partially-restored backup) gets the binding
// back on the next seed call. Pinned because this is the recovery
// path the bug-fix that introduced bind-on-seed unblocks.
func TestAdmin_SelfHealsMissingRoleBinding(t *testing.T) {
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

// PreExistingNonAdminTable: when an unrelated user is in the table
// AND no canonical admin exists, Admin returns (nil, "", nil) so the
// operator runbook handles the wave-0 migration explicitly. Pinned
// to prevent a regression that destructively rewrites a wave-0 row.
func TestAdmin_PreExistingTableSkippedWhenNoCanonicalAdmin(t *testing.T) {
	us, rb, _ := newSeedFixture(t)
	_, err := us.Create(t.Context(), users.CreateRequest{
		Email: "first@example.com", Password: "this-is-a-long-pw",
	})
	require.NoError(t, err)

	u, pw, err := seed.Admin(t.Context(), us, rb, slog.Default(), nil)
	require.NoError(t, err)
	assert.Nil(t, u)
	assert.Empty(t, pw)
}

func TestAdmin_NilStoreErrors(t *testing.T) {
	_, _, err := seed.Admin(t.Context(), nil, nil, slog.Default(), nil)
	require.Error(t, err)
}

func TestAdmin_NilRBACErrors(t *testing.T) {
	us, _, _ := newSeedFixture(t)
	_, _, err := seed.Admin(t.Context(), us, nil, slog.Default(), nil)
	require.Error(t, err)
}
