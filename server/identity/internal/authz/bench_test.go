package authz_test

import (
	"testing"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// BenchmarkAllow_GlobalScopeAllow is the bench harness the spec names. Reports ns/op for the warm allow path against a deployment-wide
// (scope_type='global') binding. Useful for tracking long-term trends; the CI gate above is the per-PR safety net.
func BenchmarkAllow_GlobalScopeAllow(b *testing.B) {
	e, err := authz.New(b.Context(), nil, nil, authz.Options{})
	if err != nil {
		b.Fatalf("construct engine: %v", err)
	}
	actor := &api.Actor{
		Principal: api.UserPrincipal(1, ""),
		Roles: []api.RoleBinding{
			{RoleID: "admin", ScopeType: api.RoleBindingScopeGlobal, ScopeID: "*"},
		},
	}
	ctx := api.WithActor(b.Context(), actor)
	resource := api.Resource{Type: "host", ID: "abc"}

	b.ResetTimer()
	for range b.N {
		_, _ = e.Allow(ctx, api.ActionHostIsolate, resource)
	}
}

// BenchmarkAllow_Deny exercises the no_matching_rule path so a regression that makes the deny branch pathologically slower (e.g.
// scanning the whole role set instead of short-circuiting) shows up in benchstat output.
func BenchmarkAllow_Deny(b *testing.B) {
	e, err := authz.New(b.Context(), nil, nil, authz.Options{})
	if err != nil {
		b.Fatalf("construct engine: %v", err)
	}
	actor := &api.Actor{
		Principal: api.UserPrincipal(1, ""),
		Roles: []api.RoleBinding{
			{RoleID: "analyst", ScopeType: api.RoleBindingScopeGlobal, ScopeID: "*"},
		},
	}
	ctx := api.WithActor(b.Context(), actor)
	resource := api.Resource{Type: "host", ID: "abc"}

	b.ResetTimer()
	for range b.N {
		_, _ = e.Allow(ctx, api.ActionHostIsolate, resource)
	}
}
