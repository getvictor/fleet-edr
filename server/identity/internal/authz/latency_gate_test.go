//go:build !race

// The latency gate is gated off the race detector. Race adds 2-20× overhead to allocations and locks, so wall-clock latency assertions
// become unreliable under -race even when the warm path is healthy. CI runs `go test ./...` with -race for correctness AND a separate
// non-race authz workflow (.github/workflows/authz.yml) that picks up this file and enforces the p99 budget.

package authz_test

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// TestAllow_P99Latency is the CI perf gate: 1000 sequential Allow
// calls, sorted, p99 must be under 1 ms. The spec's authorization
// requirement is "sub-millisecond at p99 on production hardware";
// this is the warm-path measurement (engine pre-prepared, role
// bindings already on the actor).
//
// Failure means a Rego edit, an OPA upgrade, or a Go-side change has
// pushed the chokepoint over the latency budget. Investigate before
// merging: the chokepoint runs on every privileged request.
//
// Run via .github/workflows/authz.yml (no -race), not the main test
// matrix. Skipped under -short.
// spec:server-identity-authorization/authorization-decisions-sub-millisecond-at-p99/benchmark-passes-on-the-merge-candidate
// spec:server-identity-authorization/authorization-decisions-sub-millisecond-at-p99/benchmark-regression-blocks-the-build
func TestAllow_P99Latency(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("perf gate skipped in -short mode")
	}

	const samples = 1000
	const p99Target = 1 * time.Millisecond

	e, err := authz.New(t.Context(), nil, nil, authz.Options{})
	require.NoError(t, err)

	actor := &api.Actor{
		UserID: 1,
		Roles: []api.RoleBinding{
			{RoleID: "admin", ScopeType: api.RoleBindingScopeGlobal, ScopeID: "*"},
		},
	}
	ctx := api.WithActor(t.Context(), actor)
	resource := api.Resource{Type: "host", ID: "abc"}

	// Warm-up: a couple of evals so the first run's compile-cache
	// misses don't pollute the sample.
	for range 5 {
		_, err := e.Allow(ctx, api.ActionHostIsolate, resource)
		require.NoError(t, err)
	}

	durations := make([]time.Duration, 0, samples)
	for range samples {
		start := time.Now()
		_, err := e.Allow(ctx, api.ActionHostIsolate, resource)
		durations = append(durations, time.Since(start))
		require.NoError(t, err)
	}

	slices.Sort(durations)
	p99 := durations[(samples*99)/100]

	if p99 >= p99Target {
		// Print the top of the distribution so the failure message
		// gives a reviewer enough to diagnose without rerunning.
		t.Errorf("p99 latency %v exceeds %v target", p99, p99Target)
		t.Logf("p50: %v  p95: %v  p99: %v  p99.9: %v",
			durations[samples/2],
			durations[(samples*95)/100],
			p99,
			durations[(samples*999)/1000])
	}
}
