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

// TestAllow_P99Latency is the CI perf gate: 1000 sequential Allow calls per trial, sorted, and the BEST trial's p99 must be under
// 1 ms. The spec's requirement is "sub-millisecond at p99 on the deployment's production hardware"; this is the warm-path
// measurement (engine pre-prepared, role bindings already on the actor).
//
// Best of several trials rather than a single one, because a single trial on a shared machine measures the code AND whatever else
// the machine was doing. p99 over 1000 samples is the tenth-worst call, which is exactly where a scheduler preemption lands, and
// the gate failed twice on branches touching nothing near this package (issue #848). The spec scopes its budget to production
// hardware, which a loaded CI runner is not, so a single trial there answers a question the spec never asked.
//
// Taking the minimum p99 across trials measures what the code is CAPABLE of, which is the property worth gating: contention is
// intermittent, so at least one trial runs without a major preemption, while a genuine regression slows every trial equally.
//
// Measured before choosing, rather than guessing at a wider budget. Idle: p99 173-210 microseconds across seven trials. Under
// sixteen-way CPU load: 488-743 microseconds, best 488. Both are inside 1 ms, so the budget itself is not the problem and does not
// need widening; the single-sample tail was. The reported failures at 1.2 ms and 8.4 ms came from full-suite memory and IO
// pressure, which is precisely the case a best-of-N reading survives and a single reading does not.
//
// Failure means a Rego edit, an OPA upgrade, or a Go-side change has pushed the chokepoint over the latency budget, since a real
// regression is present in every trial. Investigate before merging: the chokepoint runs on every privileged request.
//
// Run via .github/workflows/authz.yml (no -race), not the main test matrix. Skipped under -short.
// spec:server-identity-authorization/authorization-decisions-sub-millisecond-at-p99/benchmark-passes-on-the-merge-candidate
// spec:server-identity-authorization/authorization-decisions-sub-millisecond-at-p99/benchmark-regression-blocks-the-build
// spec:server-identity-authorization/authorization-decisions-sub-millisecond-at-p99/a-busy-machine-does-not-report-a-regression
func TestAllow_P99Latency(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("perf gate skipped in -short mode")
	}

	const samples = 1000
	const p99Target = 1 * time.Millisecond
	// Enough trials that one is likely to run un-preempted, few enough that the gate stays quick: seven trials of a thousand
	// warm calls is well under a second in total.
	const trials = 7

	e, err := authz.New(t.Context(), nil, nil, authz.Options{})
	require.NoError(t, err)

	actor := &api.Actor{
		Principal: api.UserPrincipal(1, ""),
		Roles: []api.RoleBinding{
			{RoleID: "admin", ScopeType: api.RoleBindingScopeGlobal, ScopeID: "*"},
		},
	}
	ctx := api.WithActor(t.Context(), actor)
	resource := api.Resource{Type: "host", ID: "abc"}

	// Warm-up: a couple of evals so the first run's compile-cache misses don't pollute the sample.
	for range 5 {
		_, err := e.Allow(ctx, api.ActionHostIsolate, resource)
		require.NoError(t, err)
	}

	best := make([]time.Duration, 0, samples)
	var bestP99 time.Duration
	for trial := range trials {
		durations := make([]time.Duration, 0, samples)
		for range samples {
			start := time.Now()
			_, err := e.Allow(ctx, api.ActionHostIsolate, resource)
			durations = append(durations, time.Since(start))
			require.NoError(t, err)
		}
		slices.Sort(durations)
		p99 := durations[(samples*99)/100]
		if trial == 0 || p99 < bestP99 {
			bestP99, best = p99, durations
		}
		// The budget is met as soon as one trial meets it, and a further trial cannot change that. Stopping early keeps the
		// common case at one trial's cost; the remaining trials are only paid for when the first reading looks bad.
		if bestP99 < p99Target {
			break
		}
	}

	if bestP99 >= p99Target {
		// The best trial's distribution, which is the one the verdict came from. Printed so a reviewer can tell a real
		// regression (the whole distribution shifts) from a machine that was busy for all seven trials (only the tail moves).
		t.Errorf("best-of-%d p99 latency %v exceeds %v target", trials, bestP99, p99Target)
		t.Logf("best trial: p50: %v  p95: %v  p99: %v  p99.9: %v",
			best[samples/2],
			best[(samples*95)/100],
			bestP99,
			best[(samples*999)/1000])
	}
}
