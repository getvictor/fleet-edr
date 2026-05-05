//go:build integration

package oidc_test

import (
	"context"
	"errors"
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

// captureAudit is the AuditRecorder test double for JIT tests.
type captureAudit struct {
	events []api.AuditEvent
}

func (c *captureAudit) Record(_ context.Context, e api.AuditEvent) error {
	c.events = append(c.events, e)
	return nil
}

func newProvisioner(t *testing.T, allowJIT bool) (*oidc.Provisioner, *sqlx.DB, *captureAudit) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	usersStore := users.New(db)
	identitiesStore := identities.New(db)
	rbacStore := rbac.New(db)
	rec := &captureAudit{}
	p := oidc.NewProvisioner(db, usersStore, identitiesStore, rbacStore, rec, oidc.ProvisionerOptions{
		AllowJIT: allowJIT,
	})
	return p, db, rec
}

// JIT path: an unknown subject creates a user + identity + role
// binding atomically, audits user_created, returns ids the handler
// uses to mint the session.
func TestProvisionOrFind_JITNewUser(t *testing.T) {
	p, db, rec := newProvisioner(t, true)
	uid, idID, err := p.ProvisionOrFind(t.Context(), &oidc.Claims{
		Subject: "okta-sub-1",
		Email:   "alice@example.com",
		Name:    "Alice",
	})
	require.NoError(t, err)
	assert.Positive(t, uid)
	assert.Positive(t, idID)

	// Identity row exists with the right (provider, subject).
	var got struct {
		UserID   int64  `db:"user_id"`
		Provider string `db:"provider"`
		Subject  string `db:"subject"`
	}
	require.NoError(t, db.GetContext(t.Context(), &got, `
		SELECT user_id, provider, subject FROM identities WHERE id = ?
	`, idID))
	assert.Equal(t, uid, got.UserID)
	assert.Equal(t, "oidc", got.Provider)
	assert.Equal(t, "okta-sub-1", got.Subject)

	// Default role binding inserted.
	var roleID, scopeType string
	require.NoError(t, db.QueryRowxContext(t.Context(),
		`SELECT role_id, scope_type FROM role_bindings WHERE user_id = ?`, uid).
		Scan(&roleID, &scopeType))
	assert.Equal(t, oidc.DefaultJITRole, roleID)
	assert.Equal(t, "tenant", scopeType)

	// One audit row emitted with the right action + payload.
	require.Len(t, rec.events, 1)
	assert.Equal(t, api.AuditAction("auth.oidc.user_created"), rec.events[0].Action)
	assert.Equal(t, "okta-sub-1", rec.events[0].Payload["subject"])
	assert.Equal(t, oidc.DefaultJITRole, rec.events[0].Payload["role"])
}

// Existing identity short-circuits: lookup-by-(provider, subject) hits
// the existing row, no new user / identity / role binding is inserted,
// no audit row is emitted (the chokepoint will audit the subsequent
// privileged-route call separately).
func TestProvisionOrFind_ExistingIdentity(t *testing.T) {
	p, db, rec := newProvisioner(t, true)

	// Pre-seed an existing user + OIDC identity.
	uid, idID, err := p.ProvisionOrFind(t.Context(), &oidc.Claims{
		Subject: "okta-sub-2",
		Email:   "bob@example.com",
	})
	require.NoError(t, err)
	require.Len(t, rec.events, 1) // first call audited

	// Re-resolve the same subject. Must return the same ids and NOT
	// re-audit.
	uid2, idID2, err := p.ProvisionOrFind(t.Context(), &oidc.Claims{
		Subject: "okta-sub-2",
		Email:   "bob@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, uid, uid2)
	assert.Equal(t, idID, idID2)
	require.Len(t, rec.events, 1, "existing identity must not produce a second user_created audit")

	// And exactly one role binding exists (no duplicate).
	var n int
	require.NoError(t, db.QueryRowxContext(t.Context(),
		`SELECT COUNT(*) FROM role_bindings WHERE user_id = ?`, uid).Scan(&n))
	assert.Equal(t, 1, n)
}

// JIT disabled + unknown subject -> ErrUnknownIdentity. The handler
// maps this to a 403 + audit auth.oidc.unknown_subject; the
// provisioner itself does not audit (the subject hasn't been bound to
// a user, so there's nothing actor-shaped to record yet).
func TestProvisionOrFind_JITDisabledUnknownSubject(t *testing.T) {
	p, _, rec := newProvisioner(t, false)
	_, _, err := p.ProvisionOrFind(t.Context(), &oidc.Claims{
		Subject: "okta-sub-3",
		Email:   "carol@example.com",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, oidc.ErrUnknownIdentity))
	assert.Empty(t, rec.events, "no audit on JIT-disabled deny path; handler emits unknown_subject row")
}

// JIT disabled + existing identity still resolves (no JIT needed for
// pre-provisioned users). Confirms the gate is positioned correctly:
// only the create branch is conditional on AllowJIT.
func TestProvisionOrFind_JITDisabledExistingIdentity(t *testing.T) {
	// Bootstrap an existing identity via the JIT-enabled path.
	pEnabled, db, _ := newProvisioner(t, true)
	uid, _, err := pEnabled.ProvisionOrFind(t.Context(), &oidc.Claims{
		Subject: "okta-sub-4",
		Email:   "dan@example.com",
	})
	require.NoError(t, err)

	// New provisioner against the same DB with AllowJIT=false; the
	// existing identity still resolves because the gate sits on the
	// create branch only.
	pDisabled := oidc.NewProvisioner(db,
		users.New(db), identities.New(db), rbac.New(db), &captureAudit{},
		oidc.ProvisionerOptions{AllowJIT: false})
	uid2, _, err := pDisabled.ProvisionOrFind(t.Context(), &oidc.Claims{
		Subject: "okta-sub-4",
		Email:   "dan@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, uid, uid2)
}

// Empty subject is rejected with a clear error. Defense-in-depth: if a
// future IdP somehow produces an empty sub claim (it never should
// per OIDC spec), the provisioner refuses rather than creating a user
// keyed on the empty string.
func TestProvisionOrFind_EmptySubject(t *testing.T) {
	p, _, _ := newProvisioner(t, true)
	_, _, err := p.ProvisionOrFind(t.Context(), &oidc.Claims{Subject: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Subject")
}
