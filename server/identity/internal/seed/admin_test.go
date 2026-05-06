package seed_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

func newUsersStore(t *testing.T) *users.Store {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return users.New(db)
}

// SeedsOnEmptyTable: admin row inserted with NULL password +
// is_breakglass=1. The Phase 4b flow does NOT print a password
// banner — the redemption URL banner lives in cmd/main.
func TestAdmin_SeedsOnEmptyTable(t *testing.T) {
	us := newUsersStore(t)
	var stderr bytes.Buffer

	u, pw, err := seed.Admin(t.Context(), us, slog.Default(), &stderr)
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, seed.DefaultAdminEmail, u.Email)
	assert.True(t, u.IsBreakglass, "Phase 4b admin must be break-glass")
	assert.Empty(t, pw, "Phase 4b removed the password return value")
	assert.Empty(t, stderr.String(), "Phase 4b: banner is emitted by cmd/main, not by seed")
}

// Idempotent: a second seed against the same DB returns the existing
// row instead of attempting another insert. Pinned because container
// restarts re-run the seed step.
func TestAdmin_IdempotentOnRerun(t *testing.T) {
	us := newUsersStore(t)
	first, _, err := seed.Admin(t.Context(), us, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, _, err := seed.Admin(t.Context(), us, slog.Default(), nil)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, first.ID, second.ID, "second seed must return the same row")
}

// PreExistingNonAdminTable: when an unrelated user is in the table
// AND no canonical admin exists, Admin returns (nil, "", nil) so the
// operator runbook handles the wave-0 migration explicitly. Pinned
// to prevent a regression that destructively rewrites a wave-0 row.
func TestAdmin_PreExistingTableSkippedWhenNoCanonicalAdmin(t *testing.T) {
	us := newUsersStore(t)
	_, err := us.Create(t.Context(), users.CreateRequest{
		Email: "first@example.com", Password: "this-is-a-long-pw",
	})
	require.NoError(t, err)

	u, pw, err := seed.Admin(t.Context(), us, slog.Default(), nil)
	require.NoError(t, err)
	assert.Nil(t, u)
	assert.Empty(t, pw)
}

func TestAdmin_NilStoreErrors(t *testing.T) {
	_, _, err := seed.Admin(t.Context(), nil, slog.Default(), nil)
	require.Error(t, err)
}
