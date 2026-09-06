//go:build !race

// The latency gate is gated off the race detector. Race adds 2-20× overhead to allocations and locks, so wall-clock latency assertions
// become unreliable under -race even when the warm path is healthy. CI runs `go test ./...` with -race for correctness AND a separate
// non-race authz workflow (.github/workflows/authz.yml) that picks up this file and enforces the p99 budget.

package authz_test

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// TestAllow_P99Latency is the CI perf gate: 1000 sequential Allow calls per trial, sorted, and the BEST trial's p99 must be under
// 1 ms. The spec's requirement is "sub-millisecond at p99 on the deployment's production hardware"; this is the warm-path
// measurement (engine pre-prepared, role bindings already on the actor).
//
// The MEDIAN p99 across trials, not one trial's and not the best. p99 over 1000 samples is the tenth-worst call, which is exactly
// where a scheduler preemption lands, and the gate failed twice on branches touching nothing near this package (issue #848). The
// spec scopes its budget to production hardware, which a loaded CI runner is not, so a single reading there answers a question the
// spec never asked.
//
// The median is the estimator that is robust in BOTH directions, which is why it beats the two obvious alternatives. A single
// reading rejects healthy code whenever the machine is busy. The best reading has the opposite flaw, and review caught it: a
// distribution that genuinely violates the budget gets one chance per trial to produce a favourable sample, so a regression that
// pushes slightly over 1% of calls past the target would pass on whichever trial happened to see nine slow calls instead of ten.
// A median rejects both, because contention inflates a minority of trials while a real regression is present in all of them.
//
// Measured before choosing, rather than guessing at a wider budget. Idle: median 148 microseconds. Under thirty-two-way CPU load,
// twice the core count: 736 to 802 microseconds across three runs, while individual trials in those same runs reached 1.05 ms and
// 2.6 ms. So the budget itself is not too tight and does not need widening; the single-sample tail was the problem.
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
	// Odd so the median is a single reading rather than an average of two, and enough that a couple of contended trials cannot
	// move it. Seven trials of a thousand warm calls is well under a second in total.
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

	// Every trial is run: unlike a best-of-N reading there is no early exit, because a median needs the whole set.
	trialP99s := make([]time.Duration, 0, trials)
	var median []time.Duration
	for range trials {
		durations := make([]time.Duration, 0, samples)
		for range samples {
			start := time.Now()
			_, err := e.Allow(ctx, api.ActionHostIsolate, resource)
			durations = append(durations, time.Since(start))
			require.NoError(t, err)
		}
		slices.Sort(durations)
		trialP99s = append(trialP99s, durations[(samples*99)/100])
		// The trial whose p99 turns out to be the median is the one worth printing, so keep each until the verdict is known.
		if median == nil || durations[(samples*99)/100] == medianDuration(trialP99s) {
			median = durations
		}
	}

	got := medianDuration(trialP99s)
	if got >= p99Target {
		// A representative distribution, printed so a reviewer can tell a real regression (the whole distribution shifts) from
		// a machine that was busy throughout (only the tail moves). The per-trial readings show which of the two this was.
		t.Errorf("median-of-%d p99 latency %v exceeds %v target", trials, got, p99Target)
		t.Logf("p50: %v  p95: %v  p99: %v  p99.9: %v",
			median[samples/2],
			median[(samples*95)/100],
			median[(samples*99)/100],
			median[(samples*999)/1000])
		t.Logf("per-trial p99: %v", trialP99s)
	}
}

// medianDuration is the gate's reduction from per-trial p99 readings to one verdict.
//
// Extracted so it can be tested without needing a contended machine, which review pointed out the gate itself cannot arrange:
// the workload alone passes under the old single-trial implementation too, unless the runner happens to be busy, so nothing
// stopped a later change from reverting to it. TestMedianDuration covers what the choice buys, against both alternatives.
func medianDuration(ds []time.Duration) time.Duration {
	sorted := slices.Clone(ds)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

// TestMedianDuration is what stops a later change from reverting the gate to a reading that flakes or that lets a regression
// through. Review pointed out that the gate's own workload cannot do that job: it passes under the single-trial implementation
// too, unless the runner happens to be busy, so a revert would look fine on a quiet machine and start flaking later.
//
// The cases are the two failure modes the median exists to avoid, stated as data rather than as timing.
func TestMedianDuration(t *testing.T) {
	t.Parallel()

	const target = 1 * time.Millisecond
	ms := func(vs ...float64) []time.Duration {
		out := make([]time.Duration, 0, len(vs))
		for _, v := range vs {
			out = append(out, time.Duration(v*float64(time.Millisecond)))
		}
		return out
	}

	cases := []struct {
		name    string
		trials  []time.Duration
		exceeds bool
		why     string
	}{
		{
			// The flake this gate was rewritten for: healthy code, two trials caught by a busy machine.
			name:    "a couple of contended trials do not fail healthy code",
			trials:  ms(0.2, 0.2, 8.4, 0.2, 1.2, 0.2, 0.2),
			exceeds: false,
			why:     "a single reading of either outlier would have failed the build for the machine's load",
		},
		{
			// The hole in a best-of-N reading, which review caught: one favourable trial would have passed the build.
			name:    "a real regression fails even with one favourable trial",
			trials:  ms(1.4, 1.5, 0.9, 1.6, 1.5, 1.4, 1.5),
			exceeds: true,
			why:     "the best reading here is 0.9 ms, so best-of-N would have called a violating distribution healthy",
		},
		{
			name:    "a regression present in every trial fails",
			trials:  ms(1.4, 1.5, 1.6, 1.5, 1.4, 1.5, 1.6),
			exceeds: true,
			why:     "the whole distribution is over budget",
		},
		{
			name:    "healthy code passes",
			trials:  ms(0.15, 0.2, 0.18, 0.16, 0.21, 0.17, 0.19),
			exceeds: false,
		},
		{
			// Exactly at the budget is a violation, matching the gate's own >= comparison: the requirement is "under 1 ms".
			name:    "exactly at the target is a violation",
			trials:  ms(1, 1, 1, 1, 1, 1, 1),
			exceeds: true,
			why:     "the requirement is p99 under 1 ms, so the boundary itself does not comply",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := medianDuration(tc.trials)
			assert.Equal(t, tc.exceeds, got >= target, "median %v against %v target. %s", got, target, tc.why)
		})
	}
}

// TestMedianDuration_DoesNotMutateItsInput keeps the caller's per-trial readings printable in the order they were taken, which is
// what tells a reviewer whether the slow trials were consecutive (a busy stretch) or spread (a real regression).
func TestMedianDuration_DoesNotMutateItsInput(t *testing.T) {
	t.Parallel()
	in := []time.Duration{5, 1, 3}
	_ = medianDuration(in)
	assert.Equal(t, []time.Duration{5, 1, 3}, in, "the reduction must not reorder the caller's slice")
}
