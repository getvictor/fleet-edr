package authz_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/identity/api"
)

// TestPermissionsForRoleIDs_PerSeededRole pins the effective action set every seeded role confers, which is what the session probe
// hands the UI for capability gating. Covers all five built-in roles (the Gemini-expanded task 1.3) plus the wildcard-expansion,
// union, dedup, and unknown-role edges. The grants are the source of truth in policy/data/roles.json; this is the same data the
// chokepoint evaluates, so a drift between gating and enforcement fails here.
func TestPermissionsForRoleIDs_PerSeededRole(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)

	all := make([]string, 0, len(api.RegisteredActions()))
	for _, a := range api.RegisteredActions() {
		all = append(all, string(a))
	}
	sort.Strings(all)

	cases := []struct {
		name        string
		roleID      string
		wantContain []string
		wantOmit    []string
		wantExact   []string // when set, the result must equal this exactly
	}{
		{
			name:      "analyst is read plus comment only",
			roleID:    "analyst",
			wantExact: []string{"alert.comment", "alert.read", "host.read", "process.read"},
			wantOmit:  []string{"host.kill_process", "application_control.read", "alert.resolve"},
		},
		{
			name:        "senior_analyst is a superset with destructive host actions",
			roleID:      "senior_analyst",
			wantContain: []string{"host.kill_process", "host.isolate", "host.run_script", "application_control.read", "alert.resolve"},
			wantOmit:    []string{"application_control.rule_create", "enrollment.revoke", "user.invite", "audit.read"},
		},
		{
			name:        "admin includes application-control mutation verbs",
			roleID:      "admin",
			wantContain: []string{"application_control.read", "application_control.rule_create", "application_control.policy_delete", "enrollment.revoke", "user.invite", "host.kill_process"},
			wantOmit:    []string{"audit.read"},
		},
		{
			name:        "auditor adds audit.read but no mutations",
			roleID:      "auditor",
			wantContain: []string{"audit.read", "host.read", "process.read", "alert.read"},
			wantOmit:    []string{"host.kill_process", "application_control.read", "alert.comment"},
		},
		{
			name:      "super_admin expands the wildcard to the full registry",
			roleID:    "super_admin",
			wantExact: all,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.PermissionsForRoleIDs([]string{tc.roleID})

			assert.True(t, sort.StringsAreSorted(got), "permission set must be returned sorted for a stable wire shape")
			assert.NotContains(t, got, "*", "the wildcard must be expanded, never serialized")

			if tc.wantExact != nil {
				assert.Equal(t, tc.wantExact, got)
			}
			for _, a := range tc.wantContain {
				assert.Contains(t, got, a)
			}
			for _, a := range tc.wantOmit {
				assert.NotContains(t, got, a)
			}
		})
	}
}

// TestPermissionsForRoleIDs_UnionAndEdges covers the multi-role union (dedup), the unknown-role skip, and the empty input.
func TestPermissionsForRoleIDs_UnionAndEdges(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(t)

	t.Run("union of overlapping roles dedups to the superset", func(t *testing.T) {
		union := e.PermissionsForRoleIDs([]string{"analyst", "senior_analyst"})
		seniorOnly := e.PermissionsForRoleIDs([]string{"senior_analyst"})
		// analyst's grants are a subset of senior_analyst's, so the union equals senior_analyst's set with no duplicates.
		assert.Equal(t, seniorOnly, union)
	})

	t.Run("unknown role id contributes nothing", func(t *testing.T) {
		assert.Empty(t, e.PermissionsForRoleIDs([]string{"does_not_exist"}))
	})

	t.Run("empty input yields an empty set", func(t *testing.T) {
		assert.Empty(t, e.PermissionsForRoleIDs(nil))
	})

	t.Run("unknown roles are skipped but known roles still resolve", func(t *testing.T) {
		got := e.PermissionsForRoleIDs([]string{"ghost", "analyst"})
		assert.Equal(t, e.PermissionsForRoleIDs([]string{"analyst"}), got)
	})
}
