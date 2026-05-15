package authz_test

import (
	"context"
	"embed"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// rolesFS embeds the same roles.json the engine compiles into the
// policy bundle. The PBT reads it at test time so the property checks
// stay in sync with whatever role/grants list the engine is actually
// evaluating; renaming a role in roles.json without updating any test
// fixture still gets exercised by the PBT on the next run.
//
//go:embed policy/data/roles.json
var rolesFS embed.FS

const rolesPath = "policy/data/roles.json"

// TestEngine_ActionRegistryParity_PBT generates random (role x action
// x resource_type x severity x session_fresh) tuples and asserts the
// chokepoint's decision matches the policy's declared invariants for
// every sampled tuple. Properties pinned:
//
//  1. Engine.Allow never returns a non-nil error for a registered
//     action against a well-formed Resource.
//  2. Decision.Reason is one of the canonical Reason* constants.
//  3. Allow=true iff the role's grants list contains the action OR "*",
//     except when the action+resource pair requires a fresh auth
//     event and the actor's SessionFresh=false (then it denies with
//     reauth_required). The Rego policy's requires_fresh_auth covers
//     host.{isolate,kill_process,run_script} unconditionally and
//     alert.resolve when resource.severity=="critical"; the test's
//     requiresFreshAuth predicate mirrors that table.
//  4. Determinism: two Allow calls with the same input return the
//     identical Decision.
//
// The PBT complements the example-based engine tests: the table tests
// pin specific named scenarios (super_admin grants everything; analyst
// cannot host.isolate; etc.) and stay readable; the PBT covers the
// (5 roles x 20 actions x 5 resource types x severity x freshness)
// cross-product so a missing entry in roles.json or a regressed grant
// list is caught even when no example test happens to name that
// combination.
func TestEngine_ActionRegistryParity_PBT(t *testing.T) {
	engine := newEnginePBT(t)
	roleSet := loadRolesFromBundle(t)
	actionSet := api.RegisteredActions()
	roleNames := make([]string, 0, len(roleSet))
	for name := range roleSet {
		roleNames = append(roleNames, name)
	}
	slices.Sort(roleNames)

	rapid.Check(t, func(rt *rapid.T) {
		role := rapid.SampledFrom(roleNames).Draw(rt, "role")
		action := rapid.SampledFrom(actionSet).Draw(rt, "action")
		fresh := rapid.Bool().Draw(rt, "session_fresh")
		resourceType := rapid.SampledFrom([]string{"host", "alert", "policy", "user", "audit"}).
			Draw(rt, "resource_type")
		severity := rapid.SampledFrom([]string{"", "low", "high", "critical"}).Draw(rt, "severity")

		actor := api.Actor{
			UserID:       1,
			AuthMethod:   "oidc",
			SessionFresh: fresh,
			Roles: []api.RoleBinding{{
				UserID:    1,
				RoleID:    role,
				ScopeType: api.RoleBindingScopeGlobal,
				ScopeID:   "*",
			}},
		}
		ctx := api.WithActor(context.Background(), &actor)
		resource := api.Resource{
			Type:     resourceType,
			ID:       "resource-1",
			Severity: severity,
		}

		first, err := engine.Allow(ctx, action, resource)
		require.NoErrorf(rt, err, "engine errored on registered action role=%s action=%s", role, action)

		require.Containsf(rt, canonicalReasons, first.Reason,
			"non-canonical reason role=%s action=%s decision=%+v", role, action, first)

		grants := roleSet[role]
		grantsAction := slices.Contains(grants, string(action)) || slices.Contains(grants, "*")
		needsFresh := requiresFreshAuth(action, resource)

		switch {
		case grantsAction && (!needsFresh || fresh):
			require.Truef(rt, first.Allow,
				"expected allow role=%s action=%s fresh=%v decision=%+v", role, action, fresh, first)
			require.Equalf(rt, api.ReasonGranted, first.Reason,
				"granted-allow must use ReasonGranted role=%s action=%s", role, action)
		case grantsAction && needsFresh && !fresh:
			require.Falsef(rt, first.Allow,
				"reauth-required deny must not allow role=%s action=%s decision=%+v", role, action, first)
			require.Equalf(rt, api.ReasonReauthRequired, first.Reason,
				"granted action with stale session must deny with reauth_required role=%s action=%s", role, action)
		default:
			require.Falsef(rt, first.Allow,
				"role without grant must deny role=%s action=%s decision=%+v", role, action, first)
			require.Equalf(rt, api.ReasonNoMatchingRule, first.Reason,
				"non-granting role must deny with no_matching_rule role=%s action=%s", role, action)
		}

		second, err := engine.Allow(ctx, action, resource)
		require.NoError(rt, err)
		require.Equalf(rt, first, second,
			"non-deterministic decision role=%s action=%s first=%+v second=%+v",
			role, action, first, second)
	})
}

// TestEngine_NonGlobalScope_PBT covers the scope_not_yet_supported
// branch in the Rego policy. The wave-1 resolver only honors
// scope_type=='global'; bindings with 'host_group' or 'host' scope
// MAY land in the table (the column is forward-compatible with
// wave-2) but the chokepoint denies them with the distinguishable
// reason so dashboards can chart "would have been allowed under
// wave-2" as its own dimension.
//
// Property: for any role whose grants list contains the action AND
// any non-global scope_type, Engine.Allow denies with reason
// scope_not_yet_supported. For non-granting roles, the policy's
// no_matching_rule deny still wins (the scope branch only fires
// when the role would otherwise have granted).
func TestEngine_NonGlobalScope_PBT(t *testing.T) {
	engine := newEnginePBT(t)
	roleSet := loadRolesFromBundle(t)
	actionSet := api.RegisteredActions()
	roleNames := make([]string, 0, len(roleSet))
	for name := range roleSet {
		roleNames = append(roleNames, name)
	}
	slices.Sort(roleNames)

	rapid.Check(t, func(rt *rapid.T) {
		role := rapid.SampledFrom(roleNames).Draw(rt, "role")
		action := rapid.SampledFrom(actionSet).Draw(rt, "action")
		scope := rapid.SampledFrom([]api.RoleBindingScopeType{
			api.RoleBindingScopeHost,
			api.RoleBindingScopeHostGroup,
		}).Draw(rt, "scope")

		actor := api.Actor{
			UserID:       1,
			AuthMethod:   "oidc",
			SessionFresh: true,
			Roles: []api.RoleBinding{{
				UserID:    1,
				RoleID:    role,
				ScopeType: scope,
				ScopeID:   "scope-1",
			}},
		}
		ctx := api.WithActor(context.Background(), &actor)
		resource := api.Resource{
			Type: "host",
			ID:   "host-1",
		}

		got, err := engine.Allow(ctx, action, resource)
		require.NoError(rt, err)
		require.Falsef(rt, got.Allow,
			"non-global scope must never allow role=%s action=%s scope=%s decision=%+v",
			role, action, scope, got)

		grants := roleSet[role]
		grantsAction := slices.Contains(grants, string(action)) || slices.Contains(grants, "*")
		want := api.ReasonNoMatchingRule
		if grantsAction {
			want = api.ReasonScopeNotYetSupported
		}
		require.Equalf(rt, want, got.Reason,
			"unexpected deny reason role=%s action=%s scope=%s grants=%v",
			role, action, scope, grantsAction)
	})
}

// canonicalReasons is the closed set of strings api.ReasonReauthRequired
// and friends declare. The PBT asserts every decision lands in this
// set; a regression that introduces a freeform reason string fails
// here before it can drift across the audit row's `payload.reason`
// column and break the SigNoz dashboard's grouping.
var canonicalReasons = []string{
	api.ReasonGranted,
	api.ReasonNoMatchingRule,
	api.ReasonScopeNotYetSupported,
	api.ReasonActionNotRegistered,
	api.ReasonNoActor,
	api.ReasonReauthRequired,
}

// requiresFreshAuth mirrors the Rego policy's requires_fresh_auth
// predicate against the destructive-action set. Kept as a Go-side
// table so the PBT predicts the engine's decision without parsing
// Rego: a divergence between this table and policy/edr.rego is a
// real regression the PBT catches (the engine returns reauth_required
// where the table predicted granted, or vice versa).
//
// freshAuthActions is the unconditional-fresh-auth subset
// policy/edr.rego treats as destructive enough to require
// Actor.SessionFresh regardless of resource attributes. The
// alert.resolve case is conditional on resource.severity=="critical"
// and is handled inline below.
var freshAuthActions = map[api.Action]struct{}{
	api.ActionHostIsolate:     {},
	api.ActionHostKillProcess: {},
	api.ActionHostRunScript:   {},
}

func requiresFreshAuth(action api.Action, resource api.Resource) bool {
	if _, ok := freshAuthActions[action]; ok {
		return true
	}
	return action == api.ActionAlertResolve && resource.Severity == "critical"
}

// newEnginePBT builds a real Engine over the embedded policy bundle.
// audit recorder is nil (per Engine.New's doc: "Audit may be nil only
// in tests"); no async writer.
func newEnginePBT(t *testing.T) *authz.Engine {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelError}))
	e, err := authz.New(context.Background(), nil, logger, authz.Options{})
	require.NoError(t, err)
	return e
}

// loadRolesFromBundle reads policy/data/roles.json via the test's own
// embedded copy. The package's authz.policyFS embed is unexported, so
// the test can't reach it; embedding the same file from the test
// keeps the PBT in sync with the live data without exposing the
// production embed.FS.
func loadRolesFromBundle(t *testing.T) map[string][]string {
	t.Helper()
	bytesData, err := rolesFS.ReadFile(rolesPath)
	require.NoError(t, err, "read roles.json fixture")
	var doc struct {
		Roles map[string]struct {
			Grants []string `json:"grants"`
		} `json:"roles"`
	}
	require.NoError(t, json.Unmarshal(bytesData, &doc))
	out := make(map[string][]string, len(doc.Roles))
	for name, role := range doc.Roles {
		out[name] = role.Grants
	}
	require.NotEmpty(t, out, "roles.json must declare at least one role")
	return out
}

// testLogWriter routes engine error logs through t.Log so PBT shrink
// reports include the engine's own error context, not just the bare
// require failure.
type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
