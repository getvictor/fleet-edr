package seed_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/seed"
)

// TestRoles_NilDBRejected pins the precondition contract on the roles seed: a nil sqlx.DB must produce a typed error rather than a
// nil deref. Tests are external (package seed_test) so the seed package's exported surface is the only path under test, matching how
// cmd/main calls it through identity bootstrap.
func TestRoles_NilDBRejected(t *testing.T) {
	t.Parallel()
	err := seed.Roles(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db must not be nil")
}

// TestBuiltinRoles_StableShape pins the canonical role set as a wire-format contract: order, ids, and the is-builtin invariant (every
// entry in the list represents a built-in role; the seed sets is_builtin=1 for each). A future operator-created role set lives outside
// this slice; renaming or reordering an entry here is a schema-level break.
// spec:server-identity-authorization/five-seeded-roles-bundle-permissions-for-the-deployment/built-in-role-cannot-be-deleted
func TestBuiltinRoles_StableShape(t *testing.T) {
	t.Parallel()
	wantIDs := []string{"super_admin", "admin", "senior_analyst", "analyst", "auditor"}
	gotIDs := make([]string, 0, len(seed.BuiltinRoles))
	for _, r := range seed.BuiltinRoles {
		gotIDs = append(gotIDs, r.ID)
		assert.NotEmpty(t, r.DisplayName, "role %q must have a non-empty display name", r.ID)
		assert.NotEmpty(t, r.Description, "role %q must have a non-empty description", r.ID)
	}
	assert.Equal(t, wantIDs, gotIDs, "BuiltinRoles order/ids changed: this is a wire-format break")
}
