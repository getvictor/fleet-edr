//go:build integration

package tests

import (
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/testdb/full"
)

// columnInfo is one row from MySQL's INFORMATION_SCHEMA.COLUMNS.
type columnInfo struct {
	Name       string  `db:"COLUMN_NAME"`
	IsNullable string  `db:"IS_NULLABLE"`
	DataType   string  `db:"DATA_TYPE"`
	ColumnType string  `db:"COLUMN_TYPE"`
	Default    *string `db:"COLUMN_DEFAULT"`
	ColumnKey  string  `db:"COLUMN_KEY"`
}

// readColumns returns every column on table for the current database.
// Lookups go through INFORMATION_SCHEMA so the test stays independent of
// a Go-side ORM mapping.
func readColumns(t *testing.T, db *sqlx.DB, table string) map[string]columnInfo {
	t.Helper()
	rows := []columnInfo{}
	err := db.SelectContext(t.Context(), &rows, `
		SELECT COLUMN_NAME, IS_NULLABLE, DATA_TYPE, COLUMN_TYPE, COLUMN_DEFAULT, COLUMN_KEY
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
	`, table)
	require.NoErrorf(t, err, "read columns for %s", table)
	out := make(map[string]columnInfo, len(rows))
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

// tableExists reports whether the given table is present in the current
// database. The user-management tables come from CREATE TABLE IF NOT
// EXISTS, so a missing row signals a regression in identity bootstrap.
func tableExists(t *testing.T, db *sqlx.DB, table string) bool {
	t.Helper()
	var n int
	err := db.GetContext(t.Context(), &n, `
		SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
	`, table)
	require.NoErrorf(t, err, "table-exists query for %s", table)
	return n == 1
}

// TestSchema_NewTablesPresent locks in the wave-1 user-management table
// set: every new identity-context table the spec calls for must exist
// after ApplySchema. The pre-existing tables (users, sessions,
// audit_events) are checked together with the new arrivals so a
// regression that drops one of them is also caught here.
func TestSchema_NewTablesPresent(t *testing.T) {
	db := openIdentitySchema(t)

	for _, table := range []string{
		// Pre-existing identity tables.
		"users", "sessions", "audit_events",
		// New in wave 1.
		"identities", "roles", "role_bindings",
		"bootstrap_tokens", "webauthn_credentials",
	} {
		assert.Truef(t, tableExists(t, db, table), "table %q must exist after ApplySchema", table)
	}
}

// TestSchema_TenantsTableAbsent pins the inverse: the legacy `tenants`
// scaffolding table was removed when the product was finalised as a
// single-instance deployment. A regression that re-introduces it
// silently is caught here.
func TestSchema_TenantsTableAbsent(t *testing.T) {
	db := openIdentitySchema(t)
	assert.Falsef(t, tableExists(t, db, "tenants"), "tenants table must not be re-introduced; the product is single-instance")
}

// TestSchema_UsersColumnsAdded verifies the users-table additive columns
// are present with the expected nullability + defaults. password_hash
// and password_salt MUST be nullable now so an SSO-only user (no local
// credential) is representable.
func TestSchema_UsersColumnsAdded(t *testing.T) {
	db := openIdentitySchema(t)
	cols := readColumns(t, db, "users")

	cases := []struct {
		col          string
		wantNullable string
		wantDefault  *string
	}{
		{"display_name", "YES", nil},
		{"status", "NO", strPtr("active")},
		{"is_breakglass", "NO", strPtr("0")},
		{"password_hash", "YES", nil},
		{"password_salt", "YES", nil},
	}
	for _, tc := range cases {
		t.Run(tc.col, func(t *testing.T) {
			c, ok := cols[tc.col]
			require.Truef(t, ok, "column %q missing from users", tc.col)
			assert.Equal(t, tc.wantNullable, c.IsNullable, "users.%s IS_NULLABLE", tc.col)
			if tc.wantDefault == nil {
				assert.Nil(t, c.Default, "users.%s default", tc.col)
			} else {
				require.NotNil(t, c.Default, "users.%s default must be set", tc.col)
				assert.Equal(t, *tc.wantDefault, *c.Default, "users.%s default value", tc.col)
			}
		})
	}
}

// TestSchema_UsersTenantIDAbsent pins the removal: users no longer
// carries tenant_id now that the product is a single-instance
// deployment. Regression-guards against re-introducing it.
func TestSchema_UsersTenantIDAbsent(t *testing.T) {
	db := openIdentitySchema(t)
	cols := readColumns(t, db, "users")
	_, present := cols["tenant_id"]
	assert.False(t, present, "users.tenant_id must not be re-introduced")
}

// TestSchema_SessionsColumnsAdded verifies sessions gained identity_id
// (nullable, populated by future SSO + break-glass flows) and
// auth_method ('local_password' default so existing sessions stay
// loginable through the swap).
func TestSchema_SessionsColumnsAdded(t *testing.T) {
	db := openIdentitySchema(t)
	cols := readColumns(t, db, "sessions")

	identityID, ok := cols["identity_id"]
	require.True(t, ok, "sessions.identity_id missing")
	assert.Equal(t, "YES", identityID.IsNullable)

	authMethod, ok := cols["auth_method"]
	require.True(t, ok, "sessions.auth_method missing")
	assert.Equal(t, "NO", authMethod.IsNullable)
	require.NotNil(t, authMethod.Default)
	assert.Equal(t, "local_password", *authMethod.Default)
}

// TestSchema_RoleBindingsScopeShape checks the wave-1 scope columns on
// role_bindings: an ENUM scope_type with the three values the spec
// names plus the wildcard scope_id default. The chokepoint will lean
// on this shape to deny non-deployment scopes with reason
// `scope_not_yet_supported` until the wave-2 resolver ships.
func TestSchema_RoleBindingsScopeShape(t *testing.T) {
	db := openIdentitySchema(t)
	cols := readColumns(t, db, "role_bindings")

	scopeType, ok := cols["scope_type"]
	require.True(t, ok, "role_bindings.scope_type missing")
	// Pin the enum shape exactly so an additional value or a reorder
	// fails loudly. The chokepoint vocabulary depends on this exact
	// set; lowercase the column type because MySQL renders ENUM as
	// `enum(...)` in INFORMATION_SCHEMA.COLUMNS.
	assert.Equal(t,
		"enum('global','host_group','host')",
		strings.ToLower(scopeType.ColumnType),
		"role_bindings.scope_type enum contract must not drift")
	require.NotNil(t, scopeType.Default)
	assert.Equal(t, "global", *scopeType.Default)

	scopeID, ok := cols["scope_id"]
	require.True(t, ok, "role_bindings.scope_id missing")
	require.NotNil(t, scopeID.Default)
	assert.Equal(t, "*", *scopeID.Default)
}

// TestSchema_RoleBindingsTenantIDAbsent pins the removal: role_bindings
// no longer carries tenant_id now that the product is a single-instance
// deployment. Regression-guards against re-introducing it.
func TestSchema_RoleBindingsTenantIDAbsent(t *testing.T) {
	db := openIdentitySchema(t)
	cols := readColumns(t, db, "role_bindings")
	_, present := cols["tenant_id"]
	assert.False(t, present, "role_bindings.tenant_id must not be re-introduced")
}

// TestSchema_Idempotent verifies ApplySchema is safe to re-run
// against a populated database. CREATE TABLE IF NOT EXISTS makes the
// boot path's unconditional call a no-op on the second deploy; a
// regression that turns it into a hard error would surface here
// rather than in production.
func TestSchema_Idempotent(t *testing.T) {
	db := openIdentitySchema(t)
	require.NoError(t, bootstrap.ApplySchema(t.Context(), db),
		"second ApplySchema must succeed against a populated DB")
}

// TestSeed_BuiltinRoles verifies the five built-in roles seed exactly
// once, in the canonical role-id set, with is_builtin=1 (so the future
// admin API can refuse to delete them). The ID set is the wire-shape
// vocabulary OPA / Rego policy bundles will reference; a reorder or
// rename here is a contract break.
func TestSeed_BuiltinRoles(t *testing.T) {
	db := openIdentitySchema(t)

	type roleRow struct {
		ID        string `db:"id"`
		IsBuiltin bool   `db:"is_builtin"`
	}
	var rows []roleRow
	require.NoError(t, db.SelectContext(t.Context(), &rows, `SELECT id, is_builtin FROM roles ORDER BY id`))
	require.Len(t, rows, len(seed.BuiltinRoles), "exactly the canonical built-in role set must be seeded")

	want := map[string]bool{}
	for _, r := range seed.BuiltinRoles {
		want[r.ID] = true
	}
	for _, r := range rows {
		assert.Truef(t, want[r.ID], "unexpected role %q in seeded set", r.ID)
		assert.Truef(t, r.IsBuiltin, "role %q must be flagged is_builtin=1", r.ID)
	}
}

// TestSeed_Idempotent locks in the same upgrade-path invariant as the
// schema test, but for the seed step: re-running ApplySchema does not
// duplicate the role rows. The seed uses INSERT IGNORE; this test
// catches a regression that swaps it for INSERT or REPLACE.
func TestSeed_Idempotent(t *testing.T) {
	db := openIdentitySchema(t)
	require.NoError(t, bootstrap.ApplySchema(t.Context(), db))

	var roles int
	require.NoError(t, db.GetContext(t.Context(), &roles, `SELECT COUNT(*) FROM roles`))
	assert.Equal(t, len(seed.BuiltinRoles), roles, "roles seed must not duplicate on re-run")
}

// openIdentitySchema returns a fresh test DB with every bounded
// context's schema applied (via testdb/full.Open) plus a second
// identity ApplySchema call so the assertions exercise the full
// integration-test path the project's per-context tests use.
// Calling identity ApplySchema twice is itself an idempotency
// check: a regression that turns the boot-time re-apply into a
// hard error would surface here before the dedicated
// TestSchema_Idempotent runs.
func openIdentitySchema(t *testing.T) *sqlx.DB {
	t.Helper()
	db := full.Open(t)
	require.NoError(t, bootstrap.ApplySchema(t.Context(), db))
	return db
}

func strPtr(s string) *string { return &s }
