//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// TestTenantScaffolding_SchemaAndSeeds exercises the wave-1
// user-management scaffolding through the cross-context fixture.
// The setup composes every context the way cmd/fleet-edr-server does,
// so a regression that breaks one context's tenant_id ALTER (or the
// identity seed call site) shows up here even when the per-context
// tests stay green.
//
// Three invariants the test pins:
//
//  1. Identity seeded the default tenant exactly once.
//  2. Identity seeded the five built-in roles, all flagged is_builtin.
//  3. Every long-lived table from every context carries a tenant_id
//     column with the literal default 'default' so existing wave-1
//     INSERTs land in the seeded tenant without any handler changes.
//
// Wave-1 reads do NOT filter on tenant_id; this test does not assert
// that property because verifying it accurately would require
// SQL-rendering inspection across every context. The wave-1 invariant
// is human-enforced via code review; full_path_test exercises every
// existing read endpoint and would notice if a tenant_id WHERE clause
// silently broke them.
func TestTenantScaffolding_SchemaAndSeeds(t *testing.T) {
	stack := Setup(t)
	ctx := t.Context()

	// 1. Default tenant seeded exactly once.
	var tenants []struct {
		ID     string `db:"id"`
		Status string `db:"status"`
	}
	require.NoError(t, stack.DB.SelectContext(ctx, &tenants, `SELECT id, status FROM tenants`))
	require.Len(t, tenants, 1, "exactly one tenant must be seeded")
	assert.Equal(t, identityapi.DefaultTenantID, tenants[0].ID)
	assert.Equal(t, string(identityapi.TenantStatusActive), tenants[0].Status)

	// 2. Five built-in roles seeded, all flagged is_builtin.
	type roleRow struct {
		ID        string `db:"id"`
		IsBuiltin bool   `db:"is_builtin"`
	}
	var roles []roleRow
	require.NoError(t, stack.DB.SelectContext(ctx, &roles, `SELECT id, is_builtin FROM roles ORDER BY id`))
	require.Len(t, roles, 5, "five built-in roles must be seeded")
	wantRoles := map[string]bool{
		"admin":          true,
		"analyst":        true,
		"auditor":        true,
		"senior_analyst": true,
		"super_admin":    true,
	}
	for _, r := range roles {
		assert.Truef(t, wantRoles[r.ID], "unexpected role %q", r.ID)
		assert.Truef(t, r.IsBuiltin, "role %q must have is_builtin=1", r.ID)
	}

	// 3. tenant_id columns present everywhere proposal.md names with the
	// literal 'default' default. Per proposal.md, sessions gains only
	// identity_id + auth_method (tenant attribution flows via sessions.
	// user_id -> users.tenant_id). Linked-to-user tables (identities,
	// bootstrap_tokens, webauthn_credentials) inherit similarly. roles
	// is global per the authorization spec's built-in-role rationale.
	for _, table := range []string{
		"users", "role_bindings", // identity-context tenant-scoped tables
		"hosts", "alerts", // detection
		"policies",    // rules
		"commands",    // response
		"enrollments", // endpoint
	} {
		t.Run(table+".tenant_id", func(t *testing.T) {
			var nullable, dataType string
			var defaultValue *string
			err := stack.DB.QueryRowContext(ctx, `
				SELECT IS_NULLABLE, DATA_TYPE, COLUMN_DEFAULT
				FROM INFORMATION_SCHEMA.COLUMNS
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'tenant_id'
			`, table).Scan(&nullable, &dataType, &defaultValue)
			require.NoErrorf(t, err, "tenant_id missing from %s", table)
			assert.Equal(t, "NO", nullable, "tenant_id on %s must be NOT NULL", table)
			assert.Equal(t, "varchar", dataType, "tenant_id on %s must be varchar", table)
			require.NotNilf(t, defaultValue, "tenant_id on %s must have a DEFAULT", table)
			assert.Equal(t, "default", *defaultValue,
				"tenant_id on %s must default to the seeded tenant id", table)
		})
	}
}
