//go:build integration

package oidc_test

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/identities"
	"github.com/fleetdm/edr/server/identity/internal/oidc"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// mappingPolicy is the group to role mapping these tests sign in under: JIT on, analyst by default, three mapped groups.
var mappingPolicy = oidc.Policy{
	AllowJIT:    true,
	DefaultRole: "analyst",
	GroupsClaim: "groups",
	GroupRoles:  map[string]string{"edr-admins": "admin", "edr-senior": "senior_analyst", "edr-auditors": "auditor"},
}

// groupsDB is a migrated database with a factory for provisioners over it, so one test can seed users under one policy and sign them in
// under another.
type groupsDB struct {
	db  *sqlx.DB
	rec *captureAudit
}

func newGroupsDB(t *testing.T) *groupsDB {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return &groupsDB{db: db, rec: &captureAudit{}}
}

func (g *groupsDB) provisioner(policy oidc.Policy) *oidc.Provisioner {
	return oidc.NewProvisioner(g.db, users.New(g.db), identities.New(g.db), rbac.New(g.db), g.rec, oidc.ProvisionerOptions{
		PolicyFn: func(context.Context) (oidc.Policy, error) { return policy, nil },
	})
}

// ssoUser signs a subject in for the first time with no group mapping, so it exists as an SSO user holding role, and clears the audit.
func (g *groupsDB) ssoUser(t *testing.T, subject, role string) int64 {
	t.Helper()
	uid, _, err := g.provisioner(oidc.Policy{AllowJIT: true, DefaultRole: role}).
		ProvisionOrFind(t.Context(), &oidc.Claims{Subject: subject, Email: subject + "@example.com"})
	require.NoError(t, err)
	g.rec.events = nil
	return uid
}

func (g *groupsDB) roles(t *testing.T, uid int64) []string {
	t.Helper()
	roles, err := rbac.New(g.db).LiveGlobalRoles(t.Context(), uid)
	require.NoError(t, err)
	return roles
}

// withGroups is a claim set whose groups claim lists groups.
func withGroups(subject string, groups ...string) *oidc.Claims {
	listed := make([]any, len(groups))
	for i, group := range groups {
		listed[i] = group
	}
	return &oidc.Claims{Subject: subject, Email: subject + "@example.com", Raw: map[string]any{"groups": listed}}
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/joining-a-mapped-admin-group-makes-the-operator-an-admin
func TestProvisionOrFind_GroupMappedToAdminPromotesAtSignIn(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)
	uid := g.ssoUser(t, "alice", "analyst")
	p := g.provisioner(mappingPolicy)

	got, _, err := p.ProvisionOrFind(t.Context(), withGroups("alice", "edr-admins", "engineering"))
	require.NoError(t, err)
	assert.Equal(t, uid, got)
	assert.Equal(t, []string{"admin"}, g.roles(t, uid))
	require.Len(t, g.rec.events, 1)
	e := g.rec.events[0]
	assert.Equal(t, api.AuditRoleBindingUpdate, e.Action)
	assert.Equal(t, api.SystemPrincipal(), e.Actor, "the IdP mapping, not the operator, changed the role")
	assert.Equal(t, "user", e.TargetType)
	assert.Equal(t, map[string]any{"from": []string{"analyst"}, "to": "admin", "source": "oidc.groups", "groups": []string{"edr-admins"}},
		e.Payload)

	// Signing in again with the same groups changes nothing and records nothing.
	_, _, err = p.ProvisionOrFind(t.Context(), withGroups("alice", "edr-admins"))
	require.NoError(t, err)
	assert.Len(t, g.rec.events, 1)
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/leaving-the-group-returns-the-operator-to-the-default-role
func TestProvisionOrFind_LeavingTheGroupReturnsToTheDefaultRole(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		claims *oidc.Claims
	}{
		{"the claim lists no mapped group", withGroups("bob", "engineering")},
		{"the claim is empty", withGroups("bob")},
		{"the token has no groups claim", &oidc.Claims{Subject: "bob", Email: "bob@example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newGroupsDB(t)
			g.ssoUser(t, "other-admin", "admin")
			uid := g.ssoUser(t, "bob", "admin")

			_, _, err := g.provisioner(mappingPolicy).ProvisionOrFind(t.Context(), tc.claims)
			require.NoError(t, err)
			assert.Equal(t, []string{"analyst"}, g.roles(t, uid))
			require.Len(t, g.rec.events, 1)
			assert.Equal(t, []string{}, g.rec.events[0].Payload["groups"], "no mapped group matched")
		})
	}
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/the-most-privileged-mapped-role-wins
func TestProvisionOrFind_TheMostPrivilegedMappedRoleWins(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)
	uid := g.ssoUser(t, "carol", "analyst")

	_, _, err := g.provisioner(mappingPolicy).ProvisionOrFind(t.Context(),
		withGroups("carol", "edr-auditors", "engineering", "edr-senior", "edr-senior"))
	require.NoError(t, err)
	assert.Equal(t, []string{"senior_analyst"}, g.roles(t, uid))
	require.Len(t, g.rec.events, 1)
	assert.Equal(t, []string{"edr-auditors", "edr-senior"}, g.rec.events[0].Payload["groups"], "matched groups, sorted, each once")
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/a-new-account-is-created-in-its-mapped-role
func TestProvisionOrFind_ANewAccountIsCreatedInItsMappedRole(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)

	uid, _, err := g.provisioner(mappingPolicy).ProvisionOrFind(t.Context(), withGroups("dave", "edr-senior"))
	require.NoError(t, err)
	assert.Equal(t, []string{"senior_analyst"}, g.roles(t, uid))
	require.Len(t, g.rec.events, 1, "a creation records user.created and no separate role change")
	assert.Equal(t, api.AuditAction("user.created"), g.rec.events[0].Action)
	assert.Equal(t, "senior_analyst", g.rec.events[0].Payload["role"])
	assert.Equal(t, []string{"edr-senior"}, g.rec.events[0].Payload["groups"])
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/a-super-admin-keeps-their-role
func TestProvisionOrFind_ASuperAdminKeepsTheirRole(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)
	// Another admin, so the last-admin guard does not keep the role for its own reason.
	g.ssoUser(t, "other-admin", "admin")
	uid := g.ssoUser(t, "erin", "super_admin")

	_, _, err := g.provisioner(mappingPolicy).ProvisionOrFind(t.Context(), withGroups("erin", "edr-auditors"))
	require.NoError(t, err)
	assert.Equal(t, []string{"super_admin"}, g.roles(t, uid))
	assert.Empty(t, g.rec.events)
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/the-last-active-admin-keeps-their-role-and-still-signs-in
func TestProvisionOrFind_TheLastActiveAdminKeepsTheirRole(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)
	uid := g.ssoUser(t, "frank", "admin")

	got, _, err := g.provisioner(mappingPolicy).ProvisionOrFind(t.Context(), withGroups("frank", "engineering"))
	require.NoError(t, err, "the sign-in still succeeds")
	assert.Equal(t, uid, got)
	assert.Equal(t, []string{"admin"}, g.roles(t, uid))
	assert.Empty(t, g.rec.events)
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/without-a-groups-claim-sign-in-leaves-the-role-alone
func TestProvisionOrFind_WithoutAGroupsClaimTheRoleIsLeftAlone(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)
	uid := g.ssoUser(t, "grace", "senior_analyst")
	noClaim := mappingPolicy
	noClaim.GroupsClaim = ""

	_, _, err := g.provisioner(noClaim).ProvisionOrFind(t.Context(), withGroups("grace", "edr-admins"))
	require.NoError(t, err)
	assert.Equal(t, []string{"senior_analyst"}, g.roles(t, uid))
	assert.Empty(t, g.rec.events)
}

// spec:server-identity-authentication/sso-sign-in-maps-idp-groups-to-a-role/a-disabled-operator-s-role-is-not-changed
func TestProvisionOrFind_ADisabledOperatorsRoleIsNotChanged(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)
	uid := g.ssoUser(t, "ivan", "analyst")
	_, err := g.db.ExecContext(t.Context(), `UPDATE users SET status = 'disabled' WHERE id = ?`, uid)
	require.NoError(t, err)

	_, _, err = g.provisioner(mappingPolicy).ProvisionOrFind(t.Context(), withGroups("ivan", "edr-admins"))
	require.NoError(t, err)
	assert.Equal(t, []string{"analyst"}, g.roles(t, uid))
	assert.Empty(t, g.rec.events)
}

// With group mapping on, an adopted pre-provisioned account takes its mapped role rather than the staged one.
func TestProvisionOrFind_AnAdoptedAccountTakesItsMappedRole(t *testing.T) {
	t.Parallel()
	g := newGroupsDB(t)
	staged := seedProvisioned(t, g.db, "heidi@example.com", "auditor")
	claims := verifiedClaims("heidi", "heidi@example.com")
	claims.Raw = map[string]any{"groups": []any{"edr-senior"}}

	uid, _, err := g.provisioner(mappingPolicy).ProvisionOrFind(t.Context(), claims)
	require.NoError(t, err)
	assert.Equal(t, staged, uid)
	assert.Equal(t, []string{"senior_analyst"}, g.roles(t, uid))
	require.Len(t, g.rec.events, 1)
	assert.Equal(t, map[string]any{"from": []string{"auditor"}, "to": "senior_analyst", "source": "oidc.groups",
		"groups": []string{"edr-senior"}}, g.rec.events[0].Payload)
}
