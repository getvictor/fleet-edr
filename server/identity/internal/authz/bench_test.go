package authz_test

import (
	"testing"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// BenchmarkAllow_TenantScopeAllow is the bench harness the spec
// names. Reports ns/op for the warm allow path against a tenant
// binding. Useful for tracking long-term trends; the CI gate above
// is the per-PR safety net.
func BenchmarkAllow_TenantScopeAllow(b *testing.B) {
	e, err := authz.New(b.Context(), nil, nil, false, authz.Options{})
	if err != nil {
		b.Fatalf("construct engine: %v", err)
	}
	actor := &api.Actor{
		UserID:   1,
		TenantID: "default",
		Roles: []api.RoleBinding{
			{RoleID: "admin", TenantID: "default", ScopeType: api.RoleBindingScopeTenant, ScopeID: "*"},
		},
	}
	ctx := api.WithActor(b.Context(), actor)
	resource := api.Resource{TenantID: "default", Type: "host", ID: "abc"}

	b.ResetTimer()
	for range b.N {
		_, _ = e.Allow(ctx, api.ActionHostIsolate, resource)
	}
}

// BenchmarkAllow_Deny exercises the no_matching_rule path so a
// regression that makes the deny branch pathologically slower (e.g.
// scanning the whole role set instead of short-circuiting) shows up
// in benchstat output.
func BenchmarkAllow_Deny(b *testing.B) {
	e, err := authz.New(b.Context(), nil, nil, false, authz.Options{})
	if err != nil {
		b.Fatalf("construct engine: %v", err)
	}
	actor := &api.Actor{
		UserID:   1,
		TenantID: "default",
		Roles: []api.RoleBinding{
			{RoleID: "analyst", TenantID: "default", ScopeType: api.RoleBindingScopeTenant, ScopeID: "*"},
		},
	}
	ctx := api.WithActor(b.Context(), actor)
	resource := api.Resource{TenantID: "default", Type: "host", ID: "abc"}

	b.ResetTimer()
	for range b.N {
		_, _ = e.Allow(ctx, api.ActionHostIsolate, resource)
	}
}
