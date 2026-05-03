package seed

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdmin_PasswordEntropy is a sanity check that two seeded
// passwords differ. Crypto guarantees this with overwhelming
// probability; the test is here to catch an accidental "use a
// constant for determinism" regression in randomPassword.
//
// White-box test: stays in `package seed` so it can call the private
// randomPassword helper. The DB-using tests are in admin_test.go
// (package seed_test) to avoid the testdb -> identity/bootstrap ->
// identity/internal/seed cycle.
func TestAdmin_PasswordEntropy(t *testing.T) {
	a, err := randomPassword()
	require.NoError(t, err)
	b, err := randomPassword()
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}
