package authz_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// recordingAudit collects every AuditEvent the engine writes so tests
// can assert "the chokepoint emitted exactly the audit row a Phase 6
// dashboard would pivot on". Mirrors the recordingAudit pattern in
// other context tests.
type recordingAudit struct {
	mu     sync.Mutex
	events []api.AuditEvent
}

func (r *recordingAudit) Record(_ context.Context, e api.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingAudit) snapshot() []api.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]api.AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

func newEngine(t *testing.T, shadowMode bool) (*authz.Engine, *recordingAudit) {
	t.Helper()
	rec := &recordingAudit{}
	e, err := authz.New(t.Context(), rec, nil, shadowMode, authz.Options{})
	require.NoError(t, err, "construct engine")
	return e, rec
}

func actorWithRoles(uid int64, tenant string, roles ...api.RoleBinding) *api.Actor {
	return &api.Actor{
		UserID:     uid,
		TenantID:   tenant,
		AuthMethod: "local_password",
		Roles:      roles,
		// Default to fresh so the role/action matrix tests can pin
		// grant correctness without entangling Phase 5's reauth
		// window. Tests that need to exercise the stale-session deny
		// path build their actor inline and set SessionFresh=false
		// explicitly.
		SessionFresh: true,
	}
}

func tenantBinding(roleID, tenantID string) api.RoleBinding {
	return api.RoleBinding{
		RoleID:    roleID,
		TenantID:  tenantID,
		ScopeType: api.RoleBindingScopeTenant,
		ScopeID:   api.RoleBindingScopeWildcard,
	}
}

// TestAllow_RoleActionMatrix exercises every (role, action) cell the
// spec names. Failure here means a Rego edit changed the policy
// matrix in a way the table didn't expect; the matching opa-test
// suite catches the same bug from the policy side.
func TestAllow_RoleActionMatrix(t *testing.T) {
	cases := []struct {
		name      string
		roleID    string
		action    api.Action
		wantAllow bool
	}{
		// super_admin: always allowed (wildcard).
		{"super_admin host.isolate", "super_admin", api.ActionHostIsolate, true},
		{"super_admin policy.delete", "super_admin", api.ActionPolicyDelete, true},
		{"super_admin audit.read", "super_admin", api.ActionAuditRead, true},

		// admin: every host action + policy CRUD + alert lifecycle, but NOT audit.
		{"admin policy.update", "admin", api.ActionPolicyUpdate, true},
		{"admin host.isolate", "admin", api.ActionHostIsolate, true},
		{"admin alert.resolve", "admin", api.ActionAlertResolve, true},
		{"admin user.invite", "admin", api.ActionUserInvite, true},
		{"admin audit.read", "admin", api.ActionAuditRead, false},

		// senior_analyst: destructive actions yes; policy.update no.
		{"senior_analyst host.kill_process", "senior_analyst", api.ActionHostKillProcess, true},
		{"senior_analyst alert.resolve", "senior_analyst", api.ActionAlertResolve, true},
		{"senior_analyst policy.update", "senior_analyst", api.ActionPolicyUpdate, false},
		{"senior_analyst audit.read", "senior_analyst", api.ActionAuditRead, false},

		// analyst: read + comment only.
		{"analyst alert.read", "analyst", api.ActionAlertRead, true},
		{"analyst alert.comment", "analyst", api.ActionAlertComment, true},
		{"analyst alert.acknowledge", "analyst", api.ActionAlertAcknowledge, false},
		{"analyst host.isolate", "analyst", api.ActionHostIsolate, false},

		// auditor: investigative reads + audit.read; no mutation.
		{"auditor audit.read", "auditor", api.ActionAuditRead, true},
		{"auditor host.read", "auditor", api.ActionHostRead, true},
		{"auditor alert.read", "auditor", api.ActionAlertRead, true},
		{"auditor alert.comment", "auditor", api.ActionAlertComment, false},
		{"auditor host.isolate", "auditor", api.ActionHostIsolate, false},
	}
	// One engine for the whole matrix. The Rego compile is the
	// expensive part (~30ms) and the engine is read-only here (no
	// SetShadowMode calls), so 21 reuses of the same prepared query
	// keep `go test` snappy without changing any assertion.
	e, _ := newEngine(t, false)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actor := actorWithRoles(1, "default", tenantBinding(tc.roleID, "default"))
			ctx := api.WithActor(t.Context(), actor)
			d, err := e.Allow(ctx, tc.action, api.Resource{TenantID: "default", Type: "host", ID: "abc"})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAllow, d.Allow, "decision %+v", d)
		})
	}
}

// TestAllow_EveryRegisteredActionGrantedSomewhere asserts the seeded
// role matrix grants each Action constant to at least one role.
// Catches an action being added to RegisteredActions without a
// matching grant in roles.json — that action would silently produce
// no_matching_rule for every caller forever, which would land as a
// 403 the first time a real user invoked it with no obvious
// diagnosis path. The Rego-side parity check in
// TestPolicy_ActionsParity covers symbol drift; this test covers the
// "registered but unreachable" gap on top.
func TestAllow_EveryRegisteredActionGrantedSomewhere(t *testing.T) {
	e, _ := newEngine(t, false)
	// Mirror the seed/roles.go set; super_admin is the wildcard so any
	// action it doesn't grant under * would point at a parser bug. The
	// per-Action loop short-circuits on the first allow, so a wildcard
	// hit usually wins instantly.
	seededRoles := []string{"super_admin", "admin", "senior_analyst", "analyst", "auditor"}
	for _, action := range api.RegisteredActions() {
		t.Run(string(action), func(t *testing.T) {
			granted := false
			for _, role := range seededRoles {
				actor := actorWithRoles(1, "default", tenantBinding(role, "default"))
				ctx := api.WithActor(t.Context(), actor)
				d, err := e.Allow(ctx, action, api.Resource{TenantID: "default"})
				require.NoError(t, err)
				if d.Allow {
					granted = true
					break
				}
			}
			assert.Truef(t, granted,
				"action %q is registered in api.RegisteredActions but no seeded "+
					"role grants it; either add a grant in policy/data/roles.json "+
					"or remove the constant from api.RegisteredActions", action)
		})
	}
}

// TestAllow_UnregisteredAction_Denied verifies the defense-in-depth
// gate: a caller passing an action string outside RegisteredActions
// is denied with reason action_not_registered before Rego sees it.
func TestAllow_UnregisteredAction_Denied(t *testing.T) {
	e, rec := newEngine(t, false)
	actor := actorWithRoles(1, "default", tenantBinding("super_admin", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.Action("not.a.real.action"), api.Resource{TenantID: "default"})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	assert.Equal(t, "action_not_registered", d.Reason)
	require.Len(t, rec.snapshot(), 1, "unregistered actions still get audited")
	assert.Equal(t, api.AuditAction("authz.not.a.real.action"), rec.snapshot()[0].Action)
}

// TestAllow_NoActor_Denied verifies the chokepoint denies anonymous
// requests with reason no_actor and writes an audit row noting the
// regression. A handler should have rejected the request earlier;
// reaching the chokepoint without an actor is itself a signal.
func TestAllow_NoActor_Denied(t *testing.T) {
	e, rec := newEngine(t, false)
	d, err := e.Allow(t.Context(), api.ActionHostRead, api.Resource{})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	assert.Equal(t, "no_actor", d.Reason)
	require.Len(t, rec.snapshot(), 1)
}

// TestAllow_HostScope_NotYetSupported pins the wave-1 scope contract:
// a binding with scope_type=host on the matching resource is denied
// with reason scope_not_yet_supported (the wave-2 resolver isn't
// shipped). Without this assertion a wave-2 author could add the
// resolver and not realise wave-1 deployments expected the deny.
func TestAllow_HostScope_NotYetSupported(t *testing.T) {
	e, _ := newEngine(t, false)
	actor := actorWithRoles(1, "default", api.RoleBinding{
		RoleID: "admin", TenantID: "default",
		ScopeType: api.RoleBindingScopeHost, ScopeID: "abc",
	})
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{TenantID: "default", Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	assert.Equal(t, "scope_not_yet_supported", d.Reason)
}

// TestAllow_TenantGrantWinsOverHostScopeDeny guards against a Rego
// rule-ordering mistake: if an actor has BOTH a tenant binding AND a
// host-scope binding for the same role+action, the tenant grant must
// win. Otherwise the scope_not_yet_supported branch shadows real
// authorisations once wave-2 host scopes are mixed in.
func TestAllow_TenantGrantWinsOverHostScopeDeny(t *testing.T) {
	e, _ := newEngine(t, false)
	actor := actorWithRoles(1, "default",
		tenantBinding("admin", "default"),
		api.RoleBinding{RoleID: "admin", TenantID: "default", ScopeType: api.RoleBindingScopeHost, ScopeID: "abc"},
	)
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{TenantID: "default", Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	assert.Equal(t, "granted", d.Reason)
}

// TestAllow_CrossTenantDeny enforces wave-1 tenant isolation: an
// actor in tenant A is denied actions on a resource in tenant B even
// when the role would normally grant the action.
func TestAllow_CrossTenantDeny(t *testing.T) {
	e, _ := newEngine(t, false)
	actor := actorWithRoles(1, "tenant_a", tenantBinding("admin", "tenant_a"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{TenantID: "tenant_b", Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	assert.Equal(t, "no_matching_rule", d.Reason)
}

// TestAllow_ShadowMode forces Allow=true on a would-be deny and
// records the would-be decision in the audit row. The handler sees
// the override; the operator sees the underlying intent.
func TestAllow_ShadowMode(t *testing.T) {
	e, rec := newEngine(t, true)
	actor := actorWithRoles(1, "default", tenantBinding("analyst", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{TenantID: "default", Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.True(t, d.Allow, "shadow mode forces allow")
	assert.Equal(t, "shadow_mode", d.Reason)

	require.Len(t, rec.snapshot(), 1)
	row := rec.snapshot()[0]
	assert.Equal(t, "no_matching_rule", row.Payload["reason"], "audit row records the would-be deny reason")
	assert.Equal(t, true, row.Payload["shadow_mode"])
}

// TestSetShadowMode_Atomic confirms the hot-swap flag is atomic:
// flipping shadow mode mid-traffic is the production rollout pattern
// (cmd/main's SIGHUP handler reads the env var and calls
// SetShadowMode), so the swap must be visible to the next Allow call
// without a restart.
func TestSetShadowMode_Atomic(t *testing.T) {
	e, _ := newEngine(t, false)
	assert.False(t, e.ShadowMode())
	e.SetShadowMode(true)
	assert.True(t, e.ShadowMode())

	actor := actorWithRoles(1, "default", tenantBinding("analyst", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{TenantID: "default", Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.True(t, d.Allow, "shadow mode flip should be visible to the next Allow")
	assert.Equal(t, "shadow_mode", d.Reason)
}

// TestAllow_NilAuditDoesNotPanic guards the test-only path where a
// caller passes nil for the AuditRecorder. Production callers must
// supply one; tests sometimes don't.
func TestAllow_NilAuditDoesNotPanic(t *testing.T) {
	e, err := authz.New(t.Context(), nil, nil, false, authz.Options{})
	require.NoError(t, err)
	actor := actorWithRoles(1, "default", tenantBinding("super_admin", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{TenantID: "default", Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
}
