package authz_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/identity/internal/serviceaccounts"
)

// recordingAudit collects every AuditEvent the engine writes so tests can assert "the chokepoint emitted exactly the audit row a Phase
// 6 dashboard would pivot on". Mirrors the recordingAudit pattern in other context tests.
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

func newEngine(t *testing.T) (*authz.Engine, *recordingAudit) {
	t.Helper()
	rec := &recordingAudit{}
	e, err := authz.New(t.Context(), rec, nil, authz.Options{})
	require.NoError(t, err, "construct engine")
	return e, rec
}

func actorWithRoles(uid int64, _ string, roles ...api.RoleBinding) *api.Actor {
	return &api.Actor{
		UserID:     uid,
		AuthMethod: "local_password",
		Roles:      roles,
		// Default to fresh so the role/action matrix tests can pin grant correctness without entangling the reauth window.
		// Tests that need to exercise the stale-session deny path build their actor inline and set SessionFresh=false explicitly.
		SessionFresh: true,
	}
}

func globalBinding(roleID, _ string) api.RoleBinding {
	return api.RoleBinding{
		RoleID:    roleID,
		ScopeType: api.RoleBindingScopeGlobal,
		ScopeID:   api.RoleBindingScopeWildcard,
	}
}

// TestAllow_RoleActionMatrix exercises every (role, action) cell the spec names. Failure here means a Rego edit changed the policy
// matrix in a way the table didn't expect; the matching opa-test suite catches the same bug from the policy side.
// spec:server-identity-authorization/role-bindings-carry-a-scope-so-future-scoping-is-non-breaking/deployment-wide-binding-grants-the-action
func TestAllow_RoleActionMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		roleID    string
		action    api.Action
		wantAllow bool
	}{
		// super_admin: always allowed (wildcard).
		{"super_admin host.isolate", "super_admin", api.ActionHostIsolate, true},
		{"super_admin host.run_script", "super_admin", api.ActionHostRunScript, true},
		{"super_admin audit.read", "super_admin", api.ActionAuditRead, true},

		// admin: every host action + alert lifecycle + user.invite, but NOT audit.
		{"admin host.isolate", "admin", api.ActionHostIsolate, true},
		{"admin alert.resolve", "admin", api.ActionAlertResolve, true},
		{"admin user.invite", "admin", api.ActionUserInvite, true},
		{"admin audit.read", "admin", api.ActionAuditRead, false},

		// senior_analyst: destructive actions yes; audit no.
		{"senior_analyst host.kill_process", "senior_analyst", api.ActionHostKillProcess, true},
		{"senior_analyst alert.resolve", "senior_analyst", api.ActionAlertResolve, true},
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

		// Application Control: admin manages rules; senior_analyst can
		// read but not author; analyst + auditor see neither.
		{"admin application_control.read", "admin", api.ActionAppControlRead, true},
		{"admin application_control.rule_create", "admin", api.ActionAppControlRuleCreate, true},
		{"senior_analyst application_control.read", "senior_analyst", api.ActionAppControlRead, true},
		{"senior_analyst application_control.rule_create", "senior_analyst", api.ActionAppControlRuleCreate, false},
		{"analyst application_control.read", "analyst", api.ActionAppControlRead, false},
		{"auditor application_control.rule_create", "auditor", api.ActionAppControlRuleCreate, false},
	}
	// One engine for the whole matrix. The Rego compile is the expensive part (~30ms) and the engine is read-only here, so 21 reuses of
	// the same prepared query keep `go test` snappy without changing any assertion.
	e, _ := newEngine(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			actor := actorWithRoles(1, "default", globalBinding(tc.roleID, "default"))
			ctx := api.WithActor(t.Context(), actor)
			d, err := e.Allow(ctx, tc.action, api.Resource{Type: "host", ID: "abc"})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAllow, d.Allow, "decision %+v", d)
		})
	}
}

// TestAllow_EveryRegisteredActionGrantedSomewhere asserts the seeded
// role matrix grants each Action constant to at least one role
// OTHER than super_admin. Catches an action being added to
// RegisteredActions without a matching grant in roles.json: that
// action would silently produce no_matching_rule for every caller
// forever, which would land as a 403 the first time a real user
// invoked it with no obvious diagnosis path. The Rego-side parity
// check in TestPolicy_ActionsParity covers symbol drift; this test
// covers the "registered but unreachable for real operators" gap on
// top.
//
// super_admin is excluded from the probe because its `*` wildcard
// would silently mask a new action that's only reachable by
// break-glass. Break-glass is for incident response, not routine
// operator workflows. The wildcard is exercised separately by
// TestAllow_RoleActionMatrix; here we want to know that every
// action has a non-wildcard role that can do it.
//
// The seeded role list is derived from seed.BuiltinRoles to stay in
// sync with the seeder: a future PR that introduces a new role
// picks it up automatically (and the test keeps holding the line
// "every action must reach a non-wildcard role").
func TestAllow_EveryRegisteredActionGrantedSomewhere(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)
	var roles []string
	for _, r := range seed.BuiltinRoles {
		if r.ID == "super_admin" {
			continue
		}
		roles = append(roles, r.ID)
	}
	require.NotEmptyf(t, roles,
		"seed.BuiltinRoles produced no non-wildcard roles; the seeded "+
			"matrix has changed shape and this test needs a fresh look")
	for _, action := range api.RegisteredActions() {
		t.Run(string(action), func(t *testing.T) {
			t.Parallel()
			granted := false
			for _, role := range roles {
				actor := actorWithRoles(1, "default", globalBinding(role, "default"))
				ctx := api.WithActor(t.Context(), actor)
				d, err := e.Allow(ctx, action, api.Resource{})
				require.NoError(t, err)
				if d.Allow {
					granted = true
					break
				}
			}
			assert.Truef(t, granted,
				"action %q is registered in api.RegisteredActions but no "+
					"non-wildcard seeded role grants it; either add a grant in "+
					"policy/data/roles.json (admin / senior_analyst / analyst / "+
					"auditor) or remove the constant from api.RegisteredActions",
				action)
		})
	}
}

// TestAllow_UnregisteredAction_Denied verifies the defense-in-depth gate: a caller passing an action string outside RegisteredActions
// is denied with reason action_not_registered before Rego sees it.
// spec:server-identity-authorization/every-privileged-action-funnels-through-one-authorization-chokepoint/unregistered-action-is-denied-as-defense-in-depth
func TestAllow_UnregisteredAction_Denied(t *testing.T) {
	t.Parallel()
	e, rec := newEngine(t)
	actor := actorWithRoles(1, "default", globalBinding("super_admin", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.Action("not.a.real.action"), api.Resource{})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	assert.Equal(t, "action_not_registered", d.Reason)
	require.Len(t, rec.snapshot(), 1, "unregistered actions still get audited")
	assert.Equal(t, api.AuditAction("authz.not.a.real.action"), rec.snapshot()[0].Action)
}

// TestAllow_NoActor_Denied verifies the chokepoint denies anonymous requests with reason no_actor and writes an audit row noting the
// regression. A handler should have rejected the request earlier; reaching the chokepoint without an actor is itself a signal.
func TestAllow_NoActor_Denied(t *testing.T) {
	t.Parallel()
	e, rec := newEngine(t)
	d, err := e.Allow(t.Context(), api.ActionHostRead, api.Resource{})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	assert.Equal(t, "no_actor", d.Reason)
	require.Len(t, rec.snapshot(), 1)
}

// TestAllow_HostScope_NotYetSupported pins the wave-1 scope contract: a binding with scope_type=host on the matching resource is
// denied with reason scope_not_yet_supported (the wave-2 resolver isn't shipped). Without this assertion a wave-2 author could add the
// resolver and not realise wave-1 deployments expected the deny.
// spec:server-identity-authorization/role-bindings-carry-a-scope-so-future-scoping-is-non-breaking/host-scoped-binding-does-not-grant-the-action-in-the-current-release
func TestAllow_HostScope_NotYetSupported(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)
	actor := actorWithRoles(1, "default", api.RoleBinding{
		RoleID:    "admin",
		ScopeType: api.RoleBindingScopeHost, ScopeID: "abc",
	})
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	assert.Equal(t, "scope_not_yet_supported", d.Reason)
}

// TestAllow_GlobalGrantWinsOverHostScopeDeny guards against a Rego rule-ordering mistake: if an actor has BOTH a global binding AND
// a host-scope binding for the same role+action, the global grant must win. Otherwise the scope_not_yet_supported branch shadows real
// authorisations once wave-2 host scopes are mixed in.
func TestAllow_GlobalGrantWinsOverHostScopeDeny(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)
	actor := actorWithRoles(1, "default",
		globalBinding("admin", "default"),
		api.RoleBinding{RoleID: "admin", ScopeType: api.RoleBindingScopeHost, ScopeID: "abc"},
	)
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	assert.Equal(t, "granted", d.Reason)
}

// spec:server-identity-authentication/reauthentication-is-required-for-destructive-actions/fresh-session-executes-a-destructive-action
//
// A session whose last fresh-auth event is within the reauth window executes a destructive action (host.isolate) that the role
// (admin) otherwise grants: the chokepoint allows it. SessionFresh=true is the in-window signal the Rego requires_fresh_auth rule
// reads.
func TestAllow_FreshSession_ExecutesDestructiveAction(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)
	actor := &api.Actor{
		UserID:       1,
		AuthMethod:   "local_password",
		SessionFresh: true,
		Roles:        []api.RoleBinding{globalBinding("admin", "default")},
	}
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "h-1"})
	require.NoError(t, err)
	assert.True(t, d.Allow, "fresh session must execute the destructive action")
	assert.Equal(t, api.ReasonGranted, d.Reason)
}

// spec:server-identity-authentication/reauthentication-is-required-for-destructive-actions/stale-session-is-challenged-before-destructive-action
//
// The same admin actor with a STALE session (SessionFresh=false) is denied the destructive action with the typed
// reauth_required reason (the UI's signal to prompt for re-authentication), the action is NOT performed (Allow=false), and the
// chokepoint records an audit row for the deny carrying decision=deny and reason=reauth_required in its payload.
func TestAllow_StaleSession_ChallengedBeforeDestructiveAction(t *testing.T) {
	t.Parallel()
	e, rec := newEngine(t)
	actor := &api.Actor{
		UserID:       1,
		AuthMethod:   "local_password",
		SessionFresh: false,
		Roles:        []api.RoleBinding{globalBinding("admin", "default")},
	}
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "h-1"})
	require.NoError(t, err)
	assert.False(t, d.Allow, "stale session must not perform the destructive action")
	assert.Equal(t, api.ReasonReauthRequired, d.Reason)

	events := rec.snapshot()
	require.Len(t, events, 1, "the reauth_required deny must be audited")
	assert.Equal(t, api.AuditAction("authz.host.isolate"), events[0].Action)
	assert.Equal(t, false, events[0].Payload["allow"], "deny decision recorded as allow=false")
	assert.Equal(t, api.ReasonReauthRequired, events[0].Payload["reason"])
}

// TestAllow_NilAuditDoesNotPanic guards the test-only path where a caller passes nil for the AuditRecorder. Production callers must
// supply one; tests sometimes don't.
func TestAllow_NilAuditDoesNotPanic(t *testing.T) {
	t.Parallel()
	e, err := authz.New(t.Context(), nil, nil, authz.Options{})
	require.NoError(t, err)
	actor := actorWithRoles(1, "default", globalBinding("super_admin", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "abc"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
}

// spec:server-identity-authorization/a-service-account-actor-is-evaluated-by-the-chokepoint-but-is-never-session-fresh/service-account-actor-authorized-purely-by-role
// spec:server-identity-authorization/a-service-account-actor-is-evaluated-by-the-chokepoint-but-is-never-session-fresh/role-without-the-action-is-denied-regardless-of-token-validity
//
// A service-account actor (AuthMethod=service_account) is evaluated by the same chokepoint as a human. It is NEVER session-fresh (a
// machine has no interactive session to re-freshen), yet the reauth freshness gate must not block it: the chokepoint exempts a
// service-account principal by identity (the policy's reauth_satisfied rule), so whether it may take a destructive, reauth-gated action
// (host.isolate) turns solely on whether its bound role grants the action. Building the actor with SessionFresh=false is what makes this
// test prove the exemption rather than merely re-testing a fresh session. senior_analyst grants host.isolate (allow, granted); analyst
// does not (deny with no_matching_rule, NOT reauth_required, so the wire response does not leak role information).
func TestAllow_ServiceAccountActor_RoleDecidesDestructiveAction(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)
	serviceAccount := func(roleID string) *api.Actor {
		return &api.Actor{
			AuthMethod:   serviceaccounts.AuthMethodServiceAccount,
			SessionFresh: false,
			Roles:        []api.RoleBinding{globalBinding(roleID, "default")},
		}
	}
	t.Run("bound role grants host.isolate so the action is allowed without a freshness challenge", func(t *testing.T) {
		t.Parallel()
		ctx := api.WithActor(t.Context(), serviceAccount("senior_analyst"))
		d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "h-1"})
		require.NoError(t, err)
		assert.True(t, d.Allow, "service account whose bound role grants host.isolate is allowed: %+v", d)
		assert.Equal(t, api.ReasonGranted, d.Reason)
	})
	t.Run("bound role lacks host.isolate so the action is denied by role, not by the freshness gate", func(t *testing.T) {
		t.Parallel()
		ctx := api.WithActor(t.Context(), serviceAccount("analyst"))
		d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "h-1"})
		require.NoError(t, err)
		assert.False(t, d.Allow)
		assert.Equal(t, api.ReasonNoMatchingRule, d.Reason, "deny must be no_matching_rule, not reauth_required")
	})
}

// spec:server-identity-authorization/five-seeded-roles-bundle-permissions-for-the-deployment/admin-holds-sso-manage-analyst-does-not
//
// sso.manage gates reading and mutating the deployment's stored OIDC configuration. The seeded matrix grants it to admin explicitly and
// to super_admin via the wildcard; senior_analyst, analyst, and auditor must be denied with no_matching_rule (sso.manage is not
// reauth-gated, so the deny is role-shaped).
func TestAllow_SSOManage_OnlyAdminAndSuperAdmin(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)
	cases := []struct {
		roleID    string
		wantAllow bool
	}{
		{"super_admin", true},
		{"admin", true},
		{"senior_analyst", false},
		{"analyst", false},
		{"auditor", false},
	}
	for _, tc := range cases {
		t.Run(tc.roleID, func(t *testing.T) {
			t.Parallel()
			actor := actorWithRoles(1, "default", globalBinding(tc.roleID, "default"))
			ctx := api.WithActor(t.Context(), actor)
			d, err := e.Allow(ctx, api.ActionSSOManage, api.Resource{Type: "sso_config"})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAllow, d.Allow, "decision %+v", d)
			if !tc.wantAllow {
				assert.Equal(t, api.ReasonNoMatchingRule, d.Reason)
			}
		})
	}
}
