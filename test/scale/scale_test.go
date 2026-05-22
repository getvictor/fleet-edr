//go:build integration

// Per-PR smoke of the M12 scale runner. Boots an integration.Setup Stack, fans out a small number of hosts for a short duration,
// and asserts that observations land without errors and the latency budget holds. The full 100-host x 30-min baseline run lives
// in test/scale/baselines/ and is invoked manually via `task uat:scale`; this test exists to prove the harness itself does not rot.
//
// Build tag: `integration` matches the existing test/integration suite gate. CI's server-test job picks this up automatically via
// `./test/integration/...` plus `./test/scale/...` globs.
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

func TestM12_SmokeFiveHostsFiveSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("scale smoke skipped under -short")
	}

	stack := integration.Setup(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// Repo-relative paths resolved from this file's location (test/scale/). Pre-existing scenarios; no duplication.
	repoRoot := filepath.Join("..", "..")
	rep, err := scale.Run(ctx, scale.Options{
		ServerURL:    stack.Server.URL,
		EnrollSecret: integration.EnrollSecret,
		HostCount:    5,
		QuietRatio:   0.6, // 3 quiet, 2 active
		Duration:     5 * time.Second,
		QuietScenarioPath: filepath.Join(repoRoot,
			"test", "fakeagent", "scenarios", "quiet-host.yaml"),
		ActiveScenarioPaths: []string{
			filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1059-suspicious-exec", "scenario.yaml"),
			filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1543.001-launchagent-persistence", "scenario.yaml"),
		},
		QuietIterationGap:  500 * time.Millisecond,
		ActiveIterationGap: 200 * time.Millisecond,
		// Smoke runs against an in-process httptest server; budget is generous because the per-test MySQL container can be slow
		// under suite-wide load. The plan's 250ms budget applies only to the dedicated dev-box baseline run.
		PassP99: 2 * time.Second,
	})
	require.NoError(t, err, "scale.Run smoke")

	t.Logf("smoke: %d hosts, %d observations, p50=%s p95=%s p99=%s errors=%d",
		rep.HostCount, rep.ObservationCount, rep.LatencyP50, rep.LatencyP95, rep.LatencyP99, rep.ErrorCount)
	assert.Equal(t, 5, rep.HostCount, "host count mirrored into report")
	assert.Equal(t, 3, rep.QuietHostCount)
	assert.Equal(t, 2, rep.ActiveHostCount)
	assert.Zero(t, rep.ErrorCount, "no errors under smoke load; last error per host in PerHost")
	assert.GreaterOrEqual(t, rep.ObservationCount, 5, "every host posts at least once in 5s")
	assert.True(t, rep.Pass, "smoke must pass; FailReasons=%v", rep.FailReasons)
	assert.LessOrEqual(t, rep.LatencyP99, 2*time.Second, "smoke p99 must fit the generous budget")
}
