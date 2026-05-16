//go:build integration

package rbac_test

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// TestListLiveBindings_NilDBRejected pins the precondition: a Store constructed without a real DB must surface the misconfiguration as
// a typed error rather than nil-dereferencing inside SelectContext.
func TestListLiveBindings_NilDBRejected(t *testing.T) {
	s := rbac.New(nil)
	_, err := s.ListLiveBindings(context.Background(), 42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db must not be nil")
}

// TestListLiveBindings_EmptyTableReturnsEmptySlice covers the happy-path query against a real MySQL with no role_bindings rows.
// A user without any binding (the wave-1 default for SSO-provisioned users until they're admin-bound) must not error; the chokepoint
// then runs against an actor with an empty Roles slice and the policy returns no_matching_rule.
func TestListLiveBindings_EmptyTableReturnsEmptySlice(t *testing.T) {
	db := openSchema(t)
	uid := insertUser(t, db, "empty-bindings@test")
	s := rbac.New(db)
	got, err := s.ListLiveBindings(t.Context(), uid)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestListLiveBindings_RoundTrip pins the storage shape: a binding inserted by the seeded admin path (or wave-2's writer) round-trips
// through SelectContext into the api.RoleBinding shape with the scope_type ENUM, the wildcard scope_id, and a nil ExpiresAt for the
// never-expiring case.
func TestListLiveBindings_RoundTrip(t *testing.T) {
	db := openSchema(t)
	uid := insertUser(t, db, "active-bindings@test")
	insertBinding(t, db, bindingFixture{
		UserID: uid, RoleID: "admin",
		ScopeType: "global", ScopeID: api.RoleBindingScopeWildcard,
	})
	insertBinding(t, db, bindingFixture{
		UserID: uid, RoleID: "auditor",
		ScopeType: "global", ScopeID: api.RoleBindingScopeWildcard,
	})

	s := rbac.New(db)
	got, err := s.ListLiveBindings(t.Context(), uid)
	require.NoError(t, err)
	require.Len(t, got, 2)

	roleIDs := []string{got[0].RoleID, got[1].RoleID}
	assert.ElementsMatch(t, []string{"admin", "auditor"}, roleIDs)
	for _, b := range got {
		assert.Equal(t, uid, b.UserID)
		assert.Equal(t, api.RoleBindingScopeGlobal, b.ScopeType)
		assert.Equal(t, api.RoleBindingScopeWildcard, b.ScopeID)
		assert.Nil(t, b.ExpiresAt, "non-expiring binding must round-trip as nil ExpiresAt")
	}
}

// TestListLiveBindings_ExpiredBindingsFiltered locks in the wave-1 invariant: an expired binding (expires_at < NOW(6)) MUST NOT be
// part of the actor the chokepoint evaluates against. The Rego policy treats expired bindings as if they did not exist; this is the
// storage-side enforcement of that contract.
func TestListLiveBindings_ExpiredBindingsFiltered(t *testing.T) {
	db := openSchema(t)
	uid := insertUser(t, db, "expired-bindings@test")
	pastExp := time.Now().Add(-1 * time.Hour)
	futureExp := time.Now().Add(1 * time.Hour)
	insertBinding(t, db, bindingFixture{
		UserID: uid, RoleID: "analyst",
		ScopeType: "global", ScopeID: "*", ExpiresAt: &pastExp,
	})
	insertBinding(t, db, bindingFixture{
		UserID: uid, RoleID: "auditor",
		ScopeType: "global", ScopeID: "*", ExpiresAt: &futureExp,
	})
	insertBinding(t, db, bindingFixture{
		UserID: uid, RoleID: "admin",
		ScopeType: "global", ScopeID: "*",
	})

	s := rbac.New(db)
	got, err := s.ListLiveBindings(t.Context(), uid)
	require.NoError(t, err)

	roleIDs := make([]string, 0, len(got))
	for _, b := range got {
		roleIDs = append(roleIDs, b.RoleID)
	}
	assert.ElementsMatch(t, []string{"auditor", "admin"}, roleIDs,
		"expired analyst binding must not appear; the future and never-expiring ones must")
}

// TestListLiveBindings_OnlyTargetUser confirms the user_id WHERE clause: a binding for some other user must not bleed into the
// caller's actor.
func TestListLiveBindings_OnlyTargetUser(t *testing.T) {
	db := openSchema(t)
	uidA := insertUser(t, db, "user-a@test")
	uidB := insertUser(t, db, "user-b@test")
	insertBinding(t, db, bindingFixture{
		UserID: uidA, RoleID: "admin",
		ScopeType: "global", ScopeID: "*",
	})
	insertBinding(t, db, bindingFixture{
		UserID: uidB, RoleID: "auditor",
		ScopeType: "global", ScopeID: "*",
	})

	s := rbac.New(db)
	gotA, err := s.ListLiveBindings(t.Context(), uidA)
	require.NoError(t, err)
	require.Len(t, gotA, 1)
	assert.Equal(t, "admin", gotA[0].RoleID)

	gotB, err := s.ListLiveBindings(t.Context(), uidB)
	require.NoError(t, err)
	require.Len(t, gotB, 1)
	assert.Equal(t, "auditor", gotB[0].RoleID)
}

// openSchema returns a fresh test DB with identity's full schema + seeds applied. roles are seeded by ApplySchema so the FK-bound
// role_bindings inserts in these tests don't trip fk_role_bindings_role.
func openSchema(t *testing.T) *sqlx.DB {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return db
}

// insertUser bypasses the users.Store CRUD path; this test focuses
// on rbac, and a stub user with NULL password is sufficient.
func insertUser(t *testing.T, db *sqlx.DB, email string) int64 {
	t.Helper()
	res, err := db.ExecContext(t.Context(),
		`INSERT INTO users (email, status) VALUES (?, 'active')`,
		email)
	require.NoError(t, err, "insert user %q", email)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// bindingFixture bundles the role_bindings columns each test row pins. Collapsing the previous 8-parameter helper into a struct keeps
// individual call sites legible (named fields beat positional args when many strings have the same type) and quiets Sonar's S107
// "function has too many parameters" rule.
type bindingFixture struct {
	UserID    int64
	RoleID    string
	ScopeType string
	ScopeID   string
	ExpiresAt *time.Time
}

func insertBinding(t *testing.T, db *sqlx.DB, b bindingFixture) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		b.UserID, b.RoleID, b.ScopeType, b.ScopeID, b.ExpiresAt)
	require.NoError(t, err, "insert binding role=%s for user=%d", b.RoleID, b.UserID)
}
