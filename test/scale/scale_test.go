//go:build integration

// Per-PR smoke of the M12 scale runner. Boots an integration.Setup Stack, fans out a small number of hosts for a short duration,
// and asserts that observations land without errors and the latency budget holds. The full 100-host x 30-min baseline run lives
// in test/scale/baselines/ and is invoked manually via `task uat:scale`; this test exists to prove the harness itself does not rot.
//
// Build tag: `integration` matches the existing test/integration suite gate. The CI server-test job picks this up via the
// `./test/scale/...` glob in Taskfile.yml's test:go:server:coverage target.
package scale_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/test/integration"
	"github.com/fleetdm/edr/test/scale"
)

// Table-driven shape per CLAUDE.md's repo testing convention; even with one case today it gives an obvious extension point for
// variant smoke profiles (e.g. quiet-only, active-only, larger fan-out) without duplicating setup or assertions.
func TestM12_Smoke(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	cases := []struct {
		name             string
		opts             scale.Options
		expectQuietHosts int
		expectActive     int
		minObservations  int
	}{
		{
			name: "five hosts five seconds: mixed quiet + active",
			opts: scale.Options{
				HostCount:  5,
				QuietRatio: 0.6, // 3 quiet, 2 active
				Duration:   5 * time.Second,
				QuietScenarioPath: filepath.Join(repoRoot,
					"test", "fakeagent", "scenarios", "quiet-host.yaml"),
				ActiveScenarioPaths: []string{
					filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1059-suspicious-exec", "scenario.yaml"),
					filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1543.001-launchagent-persistence", "scenario.yaml"),
				},
				QuietIterationGap:  500 * time.Millisecond,
				ActiveIterationGap: 200 * time.Millisecond,
				// Smoke runs against an in-process httptest server; budget is generous because the per-test MySQL container
				// can be slow under suite-wide load. The plan's 250ms budget applies only to the dedicated dev-box run.
				PassP99: 2 * time.Second,
			},
			expectQuietHosts: 3,
			expectActive:     2,
			minObservations:  5, // every host posts at least once in 5s
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack := integration.Setup(t)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			opts := tc.opts
			opts.ServerURL = stack.Server.URL
			opts.EnrollSecret = integration.EnrollSecret

			rep, err := scale.Run(ctx, opts)
			require.NoError(t, err, "scale.Run smoke")

			t.Logf("smoke: %d hosts, %d observations, p50=%s p95=%s p99=%s errors=%d",
				rep.HostCount, rep.ObservationCount, rep.LatencyP50, rep.LatencyP95, rep.LatencyP99, rep.ErrorCount)
			assert.Equal(t, opts.HostCount, rep.HostCount, "host count mirrored into report")
			assert.Equal(t, tc.expectQuietHosts, rep.QuietHostCount)
			assert.Equal(t, tc.expectActive, rep.ActiveHostCount)
			assert.Zero(t, rep.ErrorCount, "no errors under smoke load; last error per host is in PerHost")
			assert.GreaterOrEqual(t, rep.ObservationCount, tc.minObservations,
				"every host should post at least once within the lane")
			assert.True(t, rep.Pass, "smoke must pass; FailReasons=%v", rep.FailReasons)
			assert.LessOrEqual(t, rep.LatencyP99, opts.PassP99, "smoke p99 must fit the generous budget")
		})
	}
}
