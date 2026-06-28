// Package scale is UAT plan milestone M12: fan out N simulated EDR hosts against one server for D duration, record client-observed
// ingest latency, exit non-zero if the documented pass criteria are breached (default p99 < 250ms, zero errors). The driver binary
// at scaledriver/ wraps Run for opt-in long-form runs (e.g. 100 hosts x 30 min on a representative dev box); a per-PR smoke test
// at scale_test.go wires Run to integration.Setup for a sub-second sanity check on every push so the harness itself does not rot.
//
// Direct-POST-to-/api/events is the load shape used here rather than driving the queue + uploader through the M2 headless binary.
// The plan's "queue depth on the agents" probe is deferred to a follow-up: M12 v1's job is to baseline server-side ingest under
// fan-in. The fakeagent library generates wire envelopes identical to what the production agent would emit, so the server side
// of the contract is fully exercised.
package scale

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/fleetdm/edr/test/fakeagent"
)

// Named constants for what would otherwise be magic numbers in defaults + tuning knobs. Grouped here so the lint-rule
// objection lands once and the runtime values stay reviewable in one place. None of these are security-sensitive; they are
// load-shape choices a contributor will want to tweak for local experiments.
const (
	defaultHostCount          = 100
	defaultQuietRatio         = 0.8
	defaultDuration           = 5 * time.Minute
	defaultQuietIterationGap  = 5 * time.Second
	defaultActiveIterationGap = 1 * time.Second
	defaultPassP99            = 250 * time.Millisecond

	// defaultQueueDepthPollInterval is the cadence at which the headless-mode driver polls each agent's GET /state for
	// queue_depth. 1 second is fast enough to catch a backed-up uploader on a 100-host fan-in (depth-build-up timescale is
	// dominated by upload-interval = 1s in headless.Options) but slow enough to keep the poller's own CPU + FD usage
	// negligible.
	defaultQueueDepthPollInterval = time.Second

	jitterFloor = 0.75 // multiplier floor for the per-host iteration gap; pairs with jitterRange below.
	jitterRange = 0.5  // multiplier added on top of floor (so the range is [floor, floor+range]).
	// enrollRetries was 3 with a fixed 500ms 429 gap; on a real server with the default 30/min per-IP rate limit and a 60s
	// Retry-After header, 100 hosts firing /api/enroll simultaneously exhausted the 3-retry budget before the token bucket
	// refilled (see baseline-direct-2026-05-26 attempt: 70/100 hosts dropped on enroll 429). Bumped to 10 with Retry-After
	// honoured per attempt: worst-case 10 retries x 60s = 10 min of enroll-retry budget, more than enough for any sane
	// per-IP cap. The cap doubles as a graceful failure mode: if the server is genuinely unreachable, 10 retries with the
	// connection-error gap (200ms) still bound the worst-case enrollment phase to a few seconds.
	enrollRetries      = 10
	enrollRetryConnGap = 200 * time.Millisecond
	enrollRetry429Gap  = 500 * time.Millisecond // fallback when Retry-After is missing / unparseable.
	enrollRetryMaxGap  = 60 * time.Second       // ceiling on parsed Retry-After; protects against pathological server values.
	httpClientTimeout  = 30 * time.Second
	httpMaxIdle        = 1024
	httpIdleTimeout    = 90 * time.Second

	// enrollStaggerInterval is the per-host gap between initial /api/enroll attempts. Each host sleeps for
	// `index * enrollStaggerInterval` before its first enroll; 600ms gives a 30/min rate-limited server plenty of
	// time to refill its token bucket between arrivals (30/min = 1/2s steady, the bucket replenishes faster than we
	// arrive). For small fan-outs (smoke tests at HostCount<=10), the cumulative stagger stays under a few seconds.
	enrollStaggerInterval = 600 * time.Millisecond
	// enrollStaggerWindow caps the cumulative stagger so a huge fan-out (1000+ hosts) doesn't push the last host out
	// of the lane window. Beyond the cap every subsequent host fires immediately and relies on the retry-with-Retry-After
	// path to absorb the 429s.
	enrollStaggerWindow = 60 * time.Second

	percentileP50 = 50
	percentileP95 = 95
	percentileP99 = 99
)

// Mode selects the load shape Run drives against the server.
//
//	ModeDirect (v1, default): each host POSTs directly to /api/events via fakeagent.PostDirect. Bypasses the agent's queue +
//	  uploader entirely. Measures server-side ingest under fan-in.
//	ModeHeadless (v2, #232): each host runs headless.Run with its own SQLite queue + uploader + control-plane socket, and a
//	  background goroutine polls the agent's GET /state for queue_depth. Adds the agent path to the load shape so a
//	  regression in the uploader (drift in batch size, backoff, etc.) shows up as rising queue depth that doesn't drain.
type Mode string

const (
	// ModeDirect is the legacy/default v1 mode. An empty Mode also resolves to ModeDirect for backward compatibility.
	ModeDirect Mode = "direct"
	// ModeHeadless is the v2 mode that drives headless.Run per simulated host. Linux/non-CGO-darwin only because the
	// headless package itself has a !darwin || !cgo build tag (the receiver stub is platform-gated).
	ModeHeadless Mode = "headless"
)

// Options configures a Run. ServerURL and EnrollSecret are required; everything else has a defaulted zero value that produces a
// useful run.
type Options struct {
	// ServerURL is the base URL of the EDR server under test (e.g. "https://localhost:8088"). No trailing slash.
	ServerURL string

	// EnrollSecret is the shared secret POSTed to /api/enroll. For local dev:server, the same value the server reads from
	// EDR_ENROLL_SECRET. For an integration.Setup Stack, integration.EnrollSecret.
	EnrollSecret string

	// HostCount is the number of simulated agents. Defaults to 100.
	HostCount int

	// QuietRatio is the fraction of hosts assigned the "quiet" scenario; the rest cycle through ActiveScenarios. Defaults to 0.8
	// per the plan (80 quiet, 20 active).
	QuietRatio float64

	// Duration is the wall-clock the load lane runs for. Defaults to 5 minutes (the developer-machine default; the plan's 30-min
	// baseline run is invoked explicitly).
	Duration time.Duration

	// QuietScenarioPath is the YAML file each quiet host loops. Required when HostCount > 0 and QuietRatio > 0.
	QuietScenarioPath string

	// ActiveScenarioPaths is the round-robin pool active hosts pick from. Required when QuietRatio < 1.
	ActiveScenarioPaths []string

	// IterationGap is the sleep between scenario iterations per host. Defaults to 5s for quiet, 1s for active. Jittered +/- 25%
	// at run time so all hosts do not synchronise.
	QuietIterationGap  time.Duration
	ActiveIterationGap time.Duration

	// AllowInsecureTLS skips the server cert check. Needed for dev:server's mkcert-signed cert when the system trust store has
	// not been primed. The integration.Setup Stack uses plain HTTP; that path ignores this knob.
	AllowInsecureTLS bool

	// PassP99 is the latency ceiling for the p99 ingest assertion. Defaults to 250ms per the plan.
	PassP99 time.Duration

	// Mode picks the load shape. Empty resolves to ModeDirect for backward compatibility (the v1 ingest-fan-in shape).
	// ModeHeadless drives headless.Run per simulated host so the queue + uploader are in the load loop, and polls each
	// agent's GET /state for queue_depth on QueueDepthPollInterval. See the Mode type comment for the trade-offs.
	Mode Mode

	// QueueDepthPollInterval is the cadence at which the headless-mode driver polls each agent's /state socket for
	// queue_depth. Zero defaults to defaultQueueDepthPollInterval (1s). Ignored when Mode != ModeHeadless.
	QueueDepthPollInterval time.Duration

	// SigNozURL is the optional base URL of a SigNoz query API (e.g. "http://localhost:8080"). When non-empty, the
	// post-run aggregation issues one query for the metric named by signozMetricHTTPServerDuration (currently
	// "http.server.duration") p99 over the run's time window and records it in Report.ServerLatencyP99 +
	// Report.ClientServerDeltaP99. A failed SigNoz query is a soft error: it surfaces in the report's SigNozQueryError
	// field but does not flip the Pass gate, since the cross-check is an operator-facing diagnostic, not a contract.
	SigNozURL string

	// PassMaxQueueDepth optionally extends the pass criteria with a max-queue-depth ceiling. When > 0, the run fails if
	// any host's max queue_depth crosses this value during the lane. Zero (the default) leaves the gate disabled until
	// the operator has captured a baseline value worth gating on (per the M12 issue's "TBD; capture observed values
	// first" guidance). Ignored when Mode != ModeHeadless.
	PassMaxQueueDepth int64

	// BacklogDSN is an optional MySQL DSN for the server's database. When non-empty, a background sampler polls the event_queue
	// processing backlog (not-yet-acked rows) on BacklogPollInterval for the life of the run and records its percentiles in the
	// Report. Empty (the default) skips the poll entirely: the per-PR smoke and the default baseline run never open a DB connection.
	// This is the opt-in server-side counterpart to the agent-side PassMaxQueueDepth gate, for the long-form lane only.
	BacklogDSN string

	// BacklogPollInterval is the cadence of the server-backlog poll. Zero defaults to defaultBacklogPollInterval (5s). Ignored when
	// BacklogDSN is empty.
	BacklogPollInterval time.Duration

	// PassMaxServerBacklog optionally extends the pass criteria with a server-side processing-backlog ceiling. When > 0, the run fails
	// if the sampled event_queue depth ever crosses this value, catching a processor-throughput regression (a single replica falling
	// behind ingest) distinct from the ingest-p99 gate. Zero (the default) leaves it disabled. Requires BacklogDSN to be set.
	PassMaxServerBacklog int64
}

// Report is the aggregate output of a Run. Every numeric field is computed across all simulated hosts; PerHost preserves the
// per-host breakdown for triage when an aggregate gate fails.
//
// v2 fields (#232 headless mode): the QueueDepth* + ServerLatency* + ClientServerDelta* fields are populated only when the
// run used Mode=ModeHeadless. Their JSON tags carry `,omitempty` so a direct-mode report still encodes to its original
// shape: committed baselines stay binary-identical until a baseline is recaptured under the new mode.
type Report struct {
	StartTime          time.Time     `json:"start_time"`
	EndTime            time.Time     `json:"end_time"`
	Duration           time.Duration `json:"duration"`
	Mode               Mode          `json:"mode,omitempty"`
	HostCount          int           `json:"host_count"`
	QuietHostCount     int           `json:"quiet_host_count"`
	ActiveHostCount    int           `json:"active_host_count"`
	ObservationCount   int           `json:"observation_count"`
	ErrorCount         int           `json:"error_count"`
	LatencyP50         time.Duration `json:"latency_p50"`
	LatencyP95         time.Duration `json:"latency_p95"`
	LatencyP99         time.Duration `json:"latency_p99"`
	LatencyMax         time.Duration `json:"latency_max"`
	ObservationsPerSec float64       `json:"observations_per_sec"`
	Pass               bool          `json:"pass"`
	PassP99            time.Duration `json:"pass_p99"`
	FailReasons        []string      `json:"fail_reasons,omitempty"`
	PerHost            []HostReport  `json:"per_host"`

	// v2 fields (headless mode only).

	// QueueDepthSamples is the total number of /state polls aggregated into the percentile fields below. Zero when the
	// run did not poll (direct mode) so a downstream reader can distinguish "headless run but the poller never sampled
	// anything" from "direct run with no queue-depth data by design."
	QueueDepthSamples int   `json:"queue_depth_samples,omitempty"`
	QueueDepthP50     int64 `json:"queue_depth_p50,omitempty"`
	QueueDepthP95     int64 `json:"queue_depth_p95,omitempty"`
	QueueDepthP99     int64 `json:"queue_depth_p99,omitempty"`
	QueueDepthMax     int64 `json:"queue_depth_max,omitempty"`

	// PassMaxQueueDepth echoes the configured ceiling. Zero (the default) means the gate was disabled.
	PassMaxQueueDepth int64 `json:"pass_max_queue_depth,omitempty"`

	// v3 fields (server-backlog poll only, populated when Options.BacklogDSN was set).

	// ServerBacklogSamples is the number of event_queue depth readings aggregated into the percentile fields below. Zero when the
	// run did not poll the server DB (the default), so a reader can tell "no backlog poll requested" from "polled, saw nothing."
	ServerBacklogSamples int   `json:"server_backlog_samples,omitempty"`
	ServerBacklogP50     int64 `json:"server_backlog_p50,omitempty"`
	ServerBacklogP95     int64 `json:"server_backlog_p95,omitempty"`
	ServerBacklogP99     int64 `json:"server_backlog_p99,omitempty"`
	ServerBacklogMax     int64 `json:"server_backlog_max,omitempty"`

	// PassMaxServerBacklog echoes the configured server-backlog ceiling. Zero (the default) means the gate was disabled.
	PassMaxServerBacklog int64 `json:"pass_max_server_backlog,omitempty"`

	// ServerLatencyP99 is the SigNoz-reported http.server.request.duration p99 over the run's time window. nil when
	// Options.SigNozURL was empty or the query failed; SigNozQueryError captures the latter.
	ServerLatencyP99 *time.Duration `json:"server_latency_p99,omitempty"`

	// ClientServerDeltaP99 is LatencyP99 minus ServerLatencyP99 (network + balancer + agent-side queue time). Positive
	// values mean the client observed more latency than the server measured; large positive deltas point at a balancer
	// or queue-side problem, not server work.
	ClientServerDeltaP99 *time.Duration `json:"client_server_delta_p99,omitempty"`

	// SigNozQueryError is the soft error from the SigNoz cross-check, if any. Set so the operator can see why the
	// cross-check didn't land without scanning logs.
	SigNozQueryError string `json:"signoz_query_error,omitempty"`
}

// HostReport is one simulated host's contribution to the aggregate Report.
type HostReport struct {
	HostID           string        `json:"host_id"`
	Scenario         string        `json:"scenario"`
	ObservationCount int           `json:"observation_count"`
	ErrorCount       int           `json:"error_count"`
	LastError        string        `json:"last_error,omitempty"`
	LatencyP99       time.Duration `json:"latency_p99"`

	// v2 fields (headless mode only). Mirror the omitempty pattern in Report so a direct-mode HostReport JSON-encodes
	// to its v1 shape.

	// EventsInjected is the final /state events_injected counter at run end. Reflects total envelopes the scenario
	// feeder pushed into the agent's control plane.
	EventsInjected int64 `json:"events_injected,omitempty"`

	// InjectErrors is the final /state inject_errors counter. Non-zero means at least one POST /event failed
	// (typically ErrBufferFull on a backed-up agent).
	InjectErrors int64 `json:"inject_errors,omitempty"`

	// QueueDepthMax is the high-water mark of queue_depth observed across all /state polls for this host.
	QueueDepthMax int64 `json:"queue_depth_max,omitempty"`
}

// Run executes the scale load lane against opts.ServerURL for opts.Duration and returns an aggregate Report. ctx is the parent
// cancellation context; if cancelled, Run returns the partial report it has accumulated plus ctx.Err(). Errors from individual
// host goroutines are recorded into the Report (HostReport.LastError + Report.ErrorCount); they do NOT abort the lane, so a
// transient server hiccup does not collapse the whole observation set.
func Run(ctx context.Context, opts Options) (Report, error) {
	opts, err := validateOptions(opts)
	if err != nil {
		return Report{}, err
	}
	if opts.Mode == ModeHeadless {
		// Linux ulimit fail-fast: each headless host opens a SQLite WAL + a unix socket + a small keepalive TCP pool, so
		// the default 1024 RLIMIT_NOFILE on most Linux dev boxes exhausts mid-run on a 100-host lane. ulimitCheckForHeadless
		// is a no-op on non-Linux (build-tagged).
		if err := ulimitCheckForHeadless(opts.HostCount); err != nil {
			return Report{}, err
		}
		return runHeadless(ctx, opts)
	}

	quiet, active, err := loadScenarios(opts)
	if err != nil {
		return Report{}, err
	}

	httpClient := buildHTTPClient(opts.AllowInsecureTLS)
	// Mode is deliberately left empty for direct runs so the `omitempty` JSON tag drops it; that's the contract the v1
	// committed baseline encodes (no "mode" key). Headless mode sets Mode explicitly in runHeadless (Copilot #277).
	rep := Report{
		StartTime: time.Now(),
		HostCount: opts.HostCount,
		PassP99:   opts.PassP99,
		PerHost:   make([]HostReport, opts.HostCount),
	}
	hosts := make([]*hostState, opts.HostCount)
	quietCutoff := int(float64(opts.HostCount) * opts.QuietRatio)
	for i := range hosts {
		st := &hostState{
			index:  i,
			hostID: uuid.NewString(),
		}
		if i < quietCutoff {
			st.scenario = quiet
			st.scenarioName = opts.QuietScenarioPath
			st.gap = opts.QuietIterationGap
			rep.QuietHostCount++
		} else {
			st.scenario = active[i%len(active)]
			st.scenarioName = opts.ActiveScenarioPaths[i%len(active)]
			st.gap = opts.ActiveIterationGap
			rep.ActiveHostCount++
		}
		// Pre-allocate the latency slice to the expected observation count (Duration / gap, padded by 2 for jitter +
		// startup variance). Grow-by-double append in the hot loop is otherwise the largest allocator in a long run and
		// can skew percentile measurements on GC-busy CI runners.
		expectedObs := int(opts.Duration/st.gap) + 2
		st.latencies = make([]time.Duration, 0, expectedObs)
		hosts[i] = st
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Duration)
	defer cancel()

	// Optional server-side backlog sampler (long-form lane only). Bound to runCtx so it stops at the run deadline alongside the hosts.
	// A bad DSN fails the run here rather than silently recording nothing.
	var backlog *backlogSampler
	if opts.BacklogDSN != "" {
		backlog, err = startBacklogSampler(runCtx, opts.BacklogDSN, opts.BacklogPollInterval)
		if err != nil {
			return Report{}, fmt.Errorf("start server-backlog sampler: %w", err)
		}
	}

	g, runCtx := errgroup.WithContext(runCtx)
	for _, h := range hosts {
		g.Go(func() error {
			h.run(runCtx, opts.ServerURL, opts.EnrollSecret, httpClient, opts.HostCount)
			return nil
		})
	}
	_ = g.Wait()
	// Cancel runCtx now that the hosts are done so the backlog sampler (bound to runCtx) exits promptly. Without this, hosts that
	// return early (e.g. mass enroll failure) would leave the sampler running until opts.Duration, and backlog.stop() would block
	// for the rest of the lane (Qodo #536). cancel() is idempotent with the deferred cancel above.
	cancel()

	rep.EndTime = time.Now()
	rep.Duration = rep.EndTime.Sub(rep.StartTime)
	aggregate(&rep, hosts, opts)
	if backlog != nil {
		backlog.stop() // waits for the poll goroutine to exit (runCtx is cancelled), then closes the DB; snapshot is final after this.
		aggregateServerBacklog(&rep, backlog.snapshot(), opts)
	}
	return rep, ctx.Err()
}

// hostState is the per-goroutine state: scenario + RNG + observation slice. Latencies accumulate locally to avoid lock contention;
// aggregate() merges them after Run returns.
type hostState struct {
	index        int
	hostID       string
	scenario     *fakeagent.Scenario
	scenarioName string
	gap          time.Duration

	mu          sync.Mutex
	latencies   []time.Duration
	errorCount  int
	lastErr     string
	postedCount int
}

// run drives one simulated host: enroll once, then loop PostDirect + sleep until ctx cancels. Errors are recorded into hostState
// but do not abort the loop; a per-host backoff would smooth retries but adds complexity disproportionate to v1's goals.
//
// Startup stagger: each host sleeps for `min(index * enrollStaggerInterval, enrollStaggerWindow)` before its first enroll
// attempt so 100 host-goroutines firing simultaneously don't pile up at /api/enroll's per-IP rate limiter (the
// baseline-direct attempt on 2026-05-26 dropped 70/100 hosts on enroll 429 with the previous zero-stagger shape). For a
// small fan-out (smoke tests at HostCount<=10) the cumulative stagger stays under a few seconds; the hostCount parameter
// is unused today but kept in the signature for symmetry with a future "scale stagger by count" variant.
func (h *hostState) run(
	ctx context.Context, serverURL, enrollSecret string, client *http.Client, hostCount int,
) {
	if err := staggeredEnrollStart(ctx, h.index, hostCount); err != nil {
		return
	}
	token, err := enrollOne(ctx, client, serverURL, enrollSecret, h.hostID)
	if err != nil {
		h.recordErr("enroll: " + err.Error())
		return
	}

	// Per-host PRNG seeded from hostID so the jitter pattern is deterministic per host but uncorrelated across hosts.
	rng := rand.New(rand.NewSource(hashSeed(h.hostID))) //nolint:gosec // jitter randomness, not security

	for ctx.Err() == nil {
		start := time.Now()
		// Thread the runner's shared http.Client through PostDirect via WithHTTPClient so the optional --insecure-tls
		// configuration applies to /api/events POSTs (not just /api/enroll). Without this option, fakeagent's PostDirect
		// would build its own default *http.Client and lose the TLS skip required for dev:server's mkcert-signed cert.
		//
		// Latency caveat (Gemini's medium-priority note on M12 v1): the wall-clock measured here covers ONE PostDirect call,
		// which may issue multiple HTTP POSTs if the scenario's envelope count exceeds fakeagent's batchSize (default 100).
		// Every M10 corpus + fakeagent starter scenario produces fewer than 100 envelopes, so today a PostDirect call =
		// one HTTP request and this measurement is per-request. If a future scenario crosses the batchSize boundary, the
		// captured latency becomes an aggregate across batches and the runner's p99 stops corresponding to server-side
		// http.server.duration p99. Either keep scenarios under one batch, raise the batchSize via WithBatchSize, or
		// instrument per-request timing through a fakeagent observer hook.
		err := h.scenario.PostDirect(ctx, serverURL, token,
			fakeagent.WithHostID(h.hostID),
			fakeagent.WithStartTime(start),
			fakeagent.WithHTTPClient(client),
		)
		latency := time.Since(start)

		// If the context cancelled while the POST was in flight, the resulting error is the runner's own shutdown signal,
		// not a server-side problem. Exit cooperatively without counting it; otherwise tight CI timing where the lane
		// deadline can fire mid-request would inflate error_count and flake the pass gate. The check uses ctx.Err()
		// rather than errors.Is(err, context.Canceled) so context.DeadlineExceeded (the typical shape when the lane's
		// own context.WithTimeout fires) is caught alongside parent-cancel propagations.
		if err != nil && ctx.Err() != nil {
			return
		}

		h.mu.Lock()
		if err != nil {
			h.errorCount++
			h.lastErr = err.Error()
		} else {
			h.latencies = append(h.latencies, latency)
			h.postedCount++
		}
		h.mu.Unlock()

		// Jittered gap: gap * [jitterFloor, jitterFloor+jitterRange]. De-synchronises hosts so the server does not see a
		// heartbeat-shaped fan-in spike.
		jittered := time.Duration(float64(h.gap) * (jitterFloor + jitterRange*rng.Float64()))
		if err := sleepCtx(ctx, jittered); err != nil {
			return
		}
	}
}

func (h *hostState) recordErr(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errorCount++
	h.lastErr = msg
}

// aggregate folds per-host latencies into the Report's percentile fields and computes pass/fail. Latencies are concatenated then
// sorted once; with ~100 hosts and ~hundreds of observations each, an O(n log n) sort over the union is well under a millisecond.
func aggregate(rep *Report, hosts []*hostState, opts Options) {
	// Pre-size the aggregate latency slice to the exact total observation count. The per-host postedCount is already known
	// here so the previous `len(hosts)*16` guess is replaced with the precise value; in a 100-host x 5-min x 1s lane the
	// guess was ~20x low and forced grow-by-double reallocations.
	totalObs := 0
	for _, h := range hosts {
		h.mu.Lock()
		totalObs += h.postedCount
		h.mu.Unlock()
	}
	all := make([]time.Duration, 0, totalObs)
	for i, h := range hosts {
		h.mu.Lock()
		hostP99 := percentile(h.latencies, percentileP99)
		hr := HostReport{
			HostID:           h.hostID,
			Scenario:         h.scenarioName,
			ObservationCount: h.postedCount,
			ErrorCount:       h.errorCount,
			LastError:        h.lastErr,
			LatencyP99:       hostP99,
		}
		rep.PerHost[i] = hr
		rep.ObservationCount += h.postedCount
		rep.ErrorCount += h.errorCount
		all = append(all, h.latencies...)
		h.mu.Unlock()
	}
	slices.Sort(all)
	rep.LatencyP50 = percentileSorted(all, percentileP50)
	rep.LatencyP95 = percentileSorted(all, percentileP95)
	rep.LatencyP99 = percentileSorted(all, percentileP99)
	if len(all) > 0 {
		rep.LatencyMax = all[len(all)-1]
	}
	if rep.Duration > 0 {
		rep.ObservationsPerSec = float64(rep.ObservationCount) / rep.Duration.Seconds()
	}
	rep.Pass = true
	if rep.ErrorCount > 0 {
		rep.Pass = false
		rep.FailReasons = append(rep.FailReasons, fmt.Sprintf("error_count > 0 (got %d)", rep.ErrorCount))
	}
	if rep.LatencyP99 > opts.PassP99 {
		rep.Pass = false
		rep.FailReasons = append(rep.FailReasons,
			fmt.Sprintf("latency_p99 %s exceeds budget %s", rep.LatencyP99, opts.PassP99))
	}
	if rep.ObservationCount == 0 {
		rep.Pass = false
		rep.FailReasons = append(rep.FailReasons, "observation_count is zero")
	}
}

// percentile sorts a copy of the slice and returns the requested percentile. Used for per-host p99 where mutating the host's
// latency slice would force locking semantics across read paths.
func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	dup := append([]time.Duration(nil), samples...)
	slices.Sort(dup)
	return percentileSorted(dup, p)
}

func percentileSorted(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	// Nearest-rank method: rank index = ceil(p/100 * N) minus 1, clamped to [0, N-1]. Matches the convention used by Prometheus
	// histogram_quantile for under-resolution buckets and produces stable values for small N. The 0.5 + truncation produces
	// banker's-style rounding without pulling in math.Round.
	const halfStep = 0.5
	const percentageScale = 100.0
	rank := int((p/percentageScale)*float64(len(sorted)) + halfStep)
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// depthPercentile is the int64 counterpart of percentileSorted, over a pre-sorted slice. Shared by the headless agent-side queue-depth
// aggregation and the server-side backlog aggregation (backlog.go), so it lives here in the always-compiled file rather than behind
// the headless build tag.
func depthPercentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	const halfStep = 0.5
	const percentageScale = 100.0
	rank := int((p/percentageScale)*float64(len(sorted)) + halfStep)
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// enrollOne hits /api/enroll for a single host_id and returns the issued host_token. Bounded retry: enrollment under fan-in can
// temporarily 429 if many hosts arrive in the same second; one short backoff covers that without papering over real failures.
// The retry-vs-terminal classification is delegated to enrollAttempt so this loop stays under the cognitive-complexity budget.
func enrollOne(ctx context.Context, client *http.Client, serverURL, enrollSecret, hostID string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"enroll_secret": enrollSecret,
		"hardware_uuid": hostID,
		"hostname":      "scale-" + hostID + ".local",
		"agent_version": "scale-driver",
		"os_version":    "macOS 14.0",
	})
	var lastErr error
	for range enrollRetries {
		token, retryGap, err := enrollAttempt(ctx, client, serverURL, body)
		if err == nil {
			return token, nil
		}
		lastErr = err
		if retryGap <= 0 {
			// enrollAttempt classified this as terminal (4xx other than 429, decode failure, missing token, request build error).
			return "", err
		}
		if err := sleepCtx(ctx, retryGap); err != nil {
			return "", err
		}
	}
	return "", lastErr
}

// enrollAttempt runs a single /api/enroll POST. Returns (token, 0, nil) on success; (_, retryGap > 0, err) when the caller
// should sleep retryGap and retry (transport error or 429); (_, 0, err) on terminal failure.
func enrollAttempt(ctx context.Context, client *http.Client, serverURL string, body []byte) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/enroll", bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", enrollRetryConnGap, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", parseRetryAfter(resp.Header.Get("Retry-After")), errors.New("HTTP 429 from /api/enroll")
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("/api/enroll HTTP %d", resp.StatusCode)
	}
	var er struct {
		HostID    string `json:"host_id"`
		HostToken string `json:"host_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return "", 0, fmt.Errorf("decode enroll response: %w", err)
	}
	if er.HostToken == "" {
		return "", 0, errors.New("enroll response missing host_token")
	}
	return er.HostToken, 0, nil
}

// staggeredEnrollStart sleeps for `index * enrollStaggerInterval` so the initial /api/enroll burst from N host-goroutines
// is spread out instead of piling up at the per-IP rate limiter in microseconds. The total spread for HostCount hosts is
// `(HostCount-1) * enrollStaggerInterval`, capped at enrollStaggerWindow so a huge fan-out doesn't push the last host out
// of the lane window. Returns ctx.Err() if cancelled mid-sleep so the caller can exit cleanly without attempting
// enrollment against a dead context. The hostCount parameter is unused today but kept in the signature for symmetry with
// the direct + headless call sites; a future "scale stagger by count" variant might consume it.
func staggeredEnrollStart(ctx context.Context, index, _ int) error {
	delay := min(time.Duration(index)*enrollStaggerInterval, enrollStaggerWindow)
	if delay <= 0 {
		return nil
	}
	return sleepCtx(ctx, delay)
}

// parseRetryAfter returns a clamped gap based on the server's Retry-After header. The server emits Retry-After in seconds
// (per /api/enroll's 60-second rate-limit refill window); a missing or unparseable header falls back to
// enrollRetry429Gap. The clamp at enrollRetryMaxGap defends against a pathological server returning a multi-hour value
// that would silently stall the entire scale lane on the enrollment phase.
func parseRetryAfter(raw string) time.Duration {
	if raw == "" {
		return enrollRetry429Gap
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return enrollRetry429Gap
	}
	gap := time.Duration(secs) * time.Second
	if gap > enrollRetryMaxGap {
		return enrollRetryMaxGap
	}
	return gap
}

// validateOptions performs every up-front argument check Run does at entry: required fields, value-range constraints, Mode
// enum membership. Extracted from Run so the entry function stays under Sonar S3776's cognitive-complexity budget. Returns
// the defaults-filled Options so the caller assigns it back as `opts, err := validateOptions(opts)`.
func validateOptions(opts Options) (Options, error) {
	if opts.ServerURL == "" {
		return opts, errors.New("scale: ServerURL is required")
	}
	if opts.EnrollSecret == "" {
		return opts, errors.New("scale: EnrollSecret is required")
	}
	opts = defaultOptions(opts)
	// Reject unknown Mode values rather than silently falling back to direct. A typo like --mode=headles would otherwise
	// run direct mode and invalidate the scale results while appearing successful (Copilot + CodeRabbit #277).
	switch opts.Mode {
	case ModeDirect, ModeHeadless:
	default:
		return opts, fmt.Errorf("scale: invalid Mode %q (allowed: %q, %q)", opts.Mode, ModeDirect, ModeHeadless)
	}
	if opts.QuietRatio < 0 || opts.QuietRatio > 1 {
		return opts, fmt.Errorf("scale: QuietRatio must be in [0,1], got %v", opts.QuietRatio)
	}
	if opts.QuietRatio > 0 && opts.QuietScenarioPath == "" {
		return opts, errors.New("scale: QuietScenarioPath is required when QuietRatio > 0")
	}
	if opts.QuietRatio < 1 && len(opts.ActiveScenarioPaths) == 0 {
		return opts, errors.New("scale: ActiveScenarioPaths is required when QuietRatio < 1")
	}
	if opts.Mode == ModeHeadless && opts.QueueDepthPollInterval <= 0 {
		// defaultOptions resolved zero -> defaultQueueDepthPollInterval, but a negative value passed in by a misconfigured
		// caller would survive that and panic in time.NewTicker (CodeRabbit #277).
		return opts, fmt.Errorf("scale: QueueDepthPollInterval must be > 0 in headless mode, got %s",
			opts.QueueDepthPollInterval)
	}
	// A server-backlog ceiling with no DSN to sample is a silent no-op: the sampler never starts, so the gate the operator
	// asked for is never evaluated and the run reports a false pass. Reject it (Copilot/Gemini/CodeRabbit #536).
	if opts.PassMaxServerBacklog > 0 && opts.BacklogDSN == "" {
		return opts, errors.New("scale: PassMaxServerBacklog requires BacklogDSN to be set")
	}
	// The server-backlog poll is only wired into the direct-mode Run; runHeadless ignores it. Reject the flags in headless
	// mode rather than silently skipping the poll, so --backlog-dsn in a headless run fails loudly instead of no-op'ing.
	if opts.Mode == ModeHeadless && opts.BacklogDSN != "" {
		return opts, errors.New("scale: BacklogDSN is only supported in direct mode, not headless")
	}
	return opts, nil
}

func defaultOptions(o Options) Options {
	if o.HostCount == 0 {
		o.HostCount = defaultHostCount
	}
	if o.QuietRatio == 0 {
		o.QuietRatio = defaultQuietRatio
	}
	if o.Duration == 0 {
		o.Duration = defaultDuration
	}
	if o.QuietIterationGap == 0 {
		o.QuietIterationGap = defaultQuietIterationGap
	}
	if o.ActiveIterationGap == 0 {
		o.ActiveIterationGap = defaultActiveIterationGap
	}
	if o.PassP99 == 0 {
		o.PassP99 = defaultPassP99
	}
	if o.Mode == "" {
		o.Mode = ModeDirect
	}
	if o.QueueDepthPollInterval == 0 {
		o.QueueDepthPollInterval = defaultQueueDepthPollInterval
	}
	return o
}

func loadScenarios(opts Options) (*fakeagent.Scenario, []*fakeagent.Scenario, error) {
	var quiet *fakeagent.Scenario
	if opts.QuietRatio > 0 {
		s, err := fakeagent.LoadScenario(opts.QuietScenarioPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load quiet scenario: %w", err)
		}
		quiet = s
	}
	active := make([]*fakeagent.Scenario, 0, len(opts.ActiveScenarioPaths))
	for _, p := range opts.ActiveScenarioPaths {
		s, err := fakeagent.LoadScenario(p)
		if err != nil {
			return nil, nil, fmt.Errorf("load active scenario %s: %w", p, err)
		}
		active = append(active, s)
	}
	return quiet, active, nil
}

// buildHTTPClient returns a client tuned for parallel small-batch POSTs: tight per-request timeout, no idle-connection ceiling
// (every host keeps its own keep-alive open), and optional self-signed TLS skip for dev:server.
//
// The TLS-skip branch trips three Sonar/CodeQL rules (go:S4830 server-cert validation, go:S5527 hostname verification, gosec
// G402). They are intentional and opt-in: the scaledriver CLI default is `--insecure-tls=false`, and the only documented
// use case is talking to a local dev:server whose cert is signed by mkcert and not yet in the system trust store. A real
// scale run against a production server passes the default (`false`) and the InsecureSkipVerify=true branch never executes.
func buildHTTPClient(insecure bool) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        httpMaxIdle,
		MaxIdleConnsPerHost: httpMaxIdle,
		IdleConnTimeout:     httpIdleTimeout,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // documented opt-in for dev:server mkcert cert; NOSONAR
	}
	return &http.Client{Timeout: httpClientTimeout, Transport: tr}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// hashSeed is a tiny FNV-1a-ish hash over the hostID so each host gets a deterministic but distinct PRNG seed without pulling in
// hash/fnv (the seed has no security value; collisions are not catastrophic).
func hashSeed(s string) int64 {
	var h int64 = 1469598103934665603
	for _, c := range []byte(s) {
		h ^= int64(c)
		h *= 1099511628211
	}
	return h
}
