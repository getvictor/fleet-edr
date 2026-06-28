//go:build integration && scalegate

// Per-RC scale gate (UAT plan #203). Unlike the per-PR M12 smoke (scale_test.go, a 5-host harness-rot check), this fans out a
// CI-feasible 200-host lane against an in-process integration.Setup stack configured with the production processor fan-out
// (ProcessConcurrency = 4) and asserts the server-side event_queue backlog stays bounded. It is the regression gate for the #535
// throughput work + the #544 deadlock-resilient claim: a reverted batching or concurrency change makes the backlog diverge here.
//
// Build tag `scalegate` keeps it out of the per-PR `-tags integration` server-test job (it runs ~2 min); the dedicated
// scale.yml workflow runs it with `-tags "integration scalegate"` on RC tags + weekly + manual dispatch. The full 500-host
// proof lives in the committed baseline (test/scale/baselines/post-535-500host.json); 200 hosts is the CI-runner-feasible count
// that still catches a processor-throughput regression via the backlog ceiling.
//
// In-process is deliberate: integration.Setup wires EnrollRatePerMinute = 1000, so 200 hosts enroll from the single CI source IP
// without tripping the production 30/min per-IP limit (the enroll-rate artifact a dev:server lane would hit). The archive is the
// in-memory MemArchive, so the gate needs only MySQL, no ClickHouse.

package scale_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/test/integration"
	"github.com/fleetdm/edr/test/scale"
)

const (
	// scaleGateHosts is the CI-runner-feasible fan-out. Large enough that a processor-throughput regression (e.g. reverting the
	// batched graph builder or the intra-replica workers) makes the backlog diverge; small enough to run on a 2-4 vCPU runner in
	// ~2 minutes alongside the in-process server.
	scaleGateHosts = 200
	// scaleGateDuration is the load-lane wall time. Long enough that the backlog trend is meaningful past the enroll ramp.
	scaleGateDuration = 90 * time.Second
	// scaleGateMaxBacklog is the event_queue processing-backlog ceiling. The post-#535 single-replica 500-host baseline held the
	// backlog at max 17; at 200 hosts with the production fan-out it should stay in the low tens. 5000 leaves generous headroom for
	// CI-runner noise while still failing decisively on the pre-#535 unbounded-growth class (that run climbed to ~37k).
	scaleGateMaxBacklog = 5000
	// scaleGateBacklogPoll is how often the gate samples the queue depth during the run.
	scaleGateBacklogPoll = 1 * time.Second
)

// TestScaleGate_BacklogBounded is the per-RC gate: 200 hosts, production processor fan-out, backlog must stay bounded.
func TestScaleGate_BacklogBounded(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Join("..", "..")
	stack := integration.Setup(t, integration.WithProcessConcurrency(4))

	ctx, cancel := context.WithTimeout(t.Context(), scaleGateDuration+60*time.Second)
	defer cancel()

	// Sample the server-side processing backlog (not-yet-acked rows) for the life of the run and keep the max. integration.Setup is
	// in-process against a per-test DB whose DSN the scale runner's BacklogDSN sampler can't reach, so the gate polls the stack's own
	// DB handle directly with the same query the runner's sampler uses.
	maxBacklog := pollMaxBacklog(ctx, t, stack)

	opts := scale.Options{
		HostCount:         scaleGateHosts,
		QuietRatio:        0.8,
		Duration:          scaleGateDuration,
		ServerURL:         stack.Server.URL,
		EnrollSecret:      integration.EnrollSecret,
		QuietScenarioPath: filepath.Join(repoRoot, "test", "fakeagent", "scenarios", "quiet-host.yaml"),
		ActiveScenarioPaths: []string{
			filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1059-suspicious-exec", "scenario.yaml"),
			filepath.Join(repoRoot, "test", "efficacy", "corpus", "T1543.001-launchagent-persistence", "scenario.yaml"),
		},
		QuietIterationGap:  500 * time.Millisecond,
		ActiveIterationGap: 200 * time.Millisecond,
		// Co-locating 200 clients + the server in one process inflates client latency, so the p99 gate is generous: the backlog
		// ceiling, not ingest latency, is this gate's signal (the dev-box baseline owns the real latency numbers).
		PassP99: 10 * time.Second,
	}

	rep, err := scale.Run(ctx, opts)
	require.NoError(t, err, "scale.Run gate lane")
	cancel() // stop the backlog sampler before reading its result

	got := maxBacklog()
	t.Logf("scale gate: %d hosts, %d observations, errors=%d, p99=%s, max_backlog=%d (ceiling %d)",
		rep.HostCount, rep.ObservationCount, rep.ErrorCount, rep.LatencyP99, got, scaleGateMaxBacklog)

	assert.Zero(t, rep.ErrorCount, "no ingest errors at the gate fan-out (enroll cap is 1000/min in-process); last error per host is in PerHost")
	assert.Greater(t, rep.ObservationCount, scaleGateHosts, "every host posts at least once over the lane")
	assert.Lessf(t, got, int64(scaleGateMaxBacklog),
		"event_queue backlog must stay bounded (got max %d, ceiling %d): a processor-throughput regression makes this diverge", got, scaleGateMaxBacklog)
}

// pollMaxBacklog starts a goroutine that samples the event_queue processing backlog every scaleGateBacklogPoll until ctx is done,
// and returns a getter for the maximum observed depth. Mirrors backlogSampler's query without needing a separate DSN.
func pollMaxBacklog(ctx context.Context, t *testing.T, stack *integration.Stack) func() int64 {
	t.Helper()
	var (
		mu       sync.Mutex
		maxDepth int64
	)
	go func() {
		ticker := time.NewTicker(scaleGateBacklogPoll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var depth int64
				if err := stack.DB.GetContext(ctx, &depth, "SELECT COUNT(*) FROM event_queue WHERE processed != 1"); err != nil {
					continue // a transient read error during a sample is not the gate's concern; the next tick re-samples
				}
				mu.Lock()
				if depth > maxDepth {
					maxDepth = depth
				}
				mu.Unlock()
			}
		}
	}()
	return func() int64 {
		mu.Lock()
		defer mu.Unlock()
		return maxDepth
	}
}
