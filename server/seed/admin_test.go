package seed

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/users"
)

func newUsersStore(t *testing.T) *users.Store {
	t.Helper()
	return users.New(store.OpenTestStore(t).DB())
}

func TestAdmin_SeedsOnEmptyTable(t *testing.T) {
	us := newUsersStore(t)
	var stderr bytes.Buffer

	u, pw, err := Admin(t.Context(), us, slog.Default(), &stderr)
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, DefaultAdminEmail, u.Email)
	assert.NotEmpty(t, pw)
	assert.Len(t, pw, 32, "24 random bytes base64url-encodes to 32 chars")

	// stderr banner printed the password exactly once.
	banner := stderr.String()
	assert.Contains(t, banner, "SEEDED ADMIN USER")
	assert.Contains(t, banner, DefaultAdminEmail)
	assert.Contains(t, banner, pw)

	// The password we returned round-trips to login: the user store can verify it.
	verified, err := us.VerifyPassword(t.Context(), DefaultAdminEmail, pw)
	require.NoError(t, err)
	assert.Equal(t, u.ID, verified.ID)
}

func TestAdmin_IdempotentWhenUsersExist(t *testing.T) {
	us := newUsersStore(t)
	// Pre-seed a different admin. Admin() should leave it alone.
	existing, err := us.Create(t.Context(), users.CreateRequest{
		Email: "first@example.com", Password: "pw",
	})
	require.NoError(t, err)

	var stderr bytes.Buffer
	u, pw, err := Admin(t.Context(), us, slog.Default(), &stderr)
	require.NoError(t, err)
	assert.Nil(t, u)
	assert.Empty(t, pw)
	assert.Empty(t, stderr.String(), "must not print the banner when seeding is skipped")

	// Pre-existing user is untouched.
	got, err := us.Get(t.Context(), existing.ID)
	require.NoError(t, err)
	assert.Equal(t, "first@example.com", got.Email)
}

func TestAdmin_NilStoreErrors(t *testing.T) {
	_, _, err := Admin(t.Context(), nil, slog.Default(), nil)
	require.Error(t, err)
}

// TestAdmin_PasswordEntropy is a sanity check that two seeded passwords differ. Crypto
// guarantees this with overwhelming probability; the test is here to catch an accidental
// "use a constant for determinism" regression in randomPassword.
func TestAdmin_PasswordEntropy(t *testing.T) {
	a, err := randomPassword()
	require.NoError(t, err)
	b, err := randomPassword()
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}
