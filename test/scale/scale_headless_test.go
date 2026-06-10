//go:build integration && (!darwin || !cgo)

// Per-PR smoke of the M12 scale runner in ModeHeadless. Companion to the direct-mode smoke in scale_test.go: same shape
// (small fan-out, short duration, integration.Setup-backed server) but exercises the agent path: each simulated host
// runs headless.Run with its own queue + uploader + control plane, the runner polls /state for queue_depth, and the
// resulting report carries the v2 fields. Build tag matches the headless package's gate (`!darwin || !cgo`) so the test
// only compiles where headless.Run is itself compileable.
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

// TestM12_Smoke_Headless pins the v2 contract: a ModeHeadless run produces queue_depth samples, events_injected counters,
// and (when SigNozURL is empty, as in this smoke) no SigNoz cross-check fields. Three hosts x five seconds is enough to
// see at least a handful of queue_depth samples (poll interval 200ms = ~25 samples per host over 5s, 75 total) and at
// least one full scenario replay per host.
func TestM12_Smoke_Headless(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	stack := integration.Setup(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	opts := scale.Options{
		ServerURL:    stack.Server.URL,
		EnrollSecret: integration.EnrollSecret,
		HostCount:    3,
		QuietRatio:   0.6, // 1 quiet + 2 active (quietCutoff = int(3*0.6) = 1)
		Duration:     5 * time.Second,
		QuietScenarioPath: filepath.Join(repoRoot,
			"test", "fakeagent", "scenarios", "quiet-host.yaml"),
		ActiveScenarioPaths: []string{
			filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1059-suspicious-exec", "scenario.yaml"),
			filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1543.001-launchagent-persistence", "scenario.yaml"),
		},
		QuietIterationGap:  500 * time.Millisecond,
		ActiveIterationGap: 200 * time.Millisecond,
		// Generous p99 budget for the smoke (the in-process MySQL container can be slow under suite-wide load); the
		// dedicated dev-box run uses the documented 250ms budget. Headless mode does not currently populate the latency
		// fields (queue path makes per-envelope client latency meaningless), so this field is set for completeness only.
		PassP99: 5 * time.Second,
		Mode:    scale.ModeHeadless,
		// Faster than the 1s default so the 5s smoke captures enough samples to assert against.
		QueueDepthPollInterval: 200 * time.Millisecond,
	}

	rep, err := scale.Run(ctx, opts)
	require.NoError(t, err, "scale.Run smoke (headless)")

	t.Logf("smoke-headless: hosts=%d injected=%d errors=%d depth_max=%d samples=%d p99=%d",
		rep.HostCount, rep.ObservationCount, rep.ErrorCount, rep.QueueDepthMax, rep.QueueDepthSamples, rep.QueueDepthP99)
	assert.Equal(t, scale.ModeHeadless, rep.Mode, "report Mode must reflect the requested mode")
	assert.Equal(t, opts.HostCount, rep.HostCount, "host count mirrored into report")
	assert.Equal(t, 1, rep.QuietHostCount, "1 quiet (floor(3 * 0.6))")
	assert.Equal(t, 2, rep.ActiveHostCount, "2 active (remainder)")
	assert.Zero(t, rep.ErrorCount, "no errors under smoke load; PerHost has LastError per host on failure")
	// Tighter lower bounds (CodeRabbit #277): expected ~75 queue-depth samples (3 hosts x 5s / 200ms = ~25 per host),
	// expected ~15 observations (3 hosts x scenario replays per second). Set the floors at 20 samples + 5 observations
	// so a regression that drops the poller cadence or breaks the scenario feeder lands here, not as a silently-passing
	// `> 0` check. The previous baseline values establish what "healthy" looks like even under suite-wide slow MySQL.
	assert.GreaterOrEqual(t, rep.QueueDepthSamples, 20, "headless mode must produce >= 20 /state poll samples (3 hosts x 5s / 200ms ~ 75)")
	assert.GreaterOrEqual(t, rep.ObservationCount, 5, "every host should inject at least one envelope within the 5s window")
	assert.True(t, rep.Pass, "smoke must pass; FailReasons=%v", rep.FailReasons)
	// SigNoz cross-check is opt-in; the smoke does not set SigNozURL so the report must carry neither the value nor
	// the soft-error field.
	assert.Nil(t, rep.ServerLatencyP99, "no SigNozURL configured; ServerLatencyP99 must be nil")
	assert.Empty(t, rep.SigNozQueryError, "no SigNozURL configured; SigNozQueryError must be empty")
}
