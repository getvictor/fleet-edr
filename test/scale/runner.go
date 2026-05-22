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

	jitterFloor        = 0.75 // multiplier floor for the per-host iteration gap; pairs with jitterRange below.
	jitterRange        = 0.5  // multiplier added on top of floor (so the range is [floor, floor+range]).
	enrollRetries      = 3
	enrollRetryConnGap = 200 * time.Millisecond
	enrollRetry429Gap  = 500 * time.Millisecond
	httpClientTimeout  = 30 * time.Second
	httpMaxIdle        = 1024
	httpIdleTimeout    = 90 * time.Second

	percentileP50 = 50
	percentileP95 = 95
	percentileP99 = 99
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
}

// Report is the aggregate output of a Run. Every numeric field is computed across all simulated hosts; PerHost preserves the
// per-host breakdown for triage when an aggregate gate fails.
type Report struct {
	StartTime          time.Time     `json:"start_time"`
	EndTime            time.Time     `json:"end_time"`
	Duration           time.Duration `json:"duration"`
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
}

// HostReport is one simulated host's contribution to the aggregate Report.
type HostReport struct {
	HostID           string        `json:"host_id"`
	Scenario         string        `json:"scenario"`
	ObservationCount int           `json:"observation_count"`
	ErrorCount       int           `json:"error_count"`
	LastError        string        `json:"last_error,omitempty"`
	LatencyP99       time.Duration `json:"latency_p99"`
}

// Run executes the scale load lane against opts.ServerURL for opts.Duration and returns an aggregate Report. ctx is the parent
// cancellation context; if cancelled, Run returns the partial report it has accumulated plus ctx.Err(). Errors from individual
// host goroutines are recorded into the Report (HostReport.LastError + Report.ErrorCount); they do NOT abort the lane, so a
// transient server hiccup does not collapse the whole observation set.
func Run(ctx context.Context, opts Options) (Report, error) {
	if opts.ServerURL == "" {
		return Report{}, errors.New("scale: ServerURL is required")
	}
	if opts.EnrollSecret == "" {
		return Report{}, errors.New("scale: EnrollSecret is required")
	}
	opts = defaultOptions(opts)
	if opts.QuietRatio < 0 || opts.QuietRatio > 1 {
		return Report{}, fmt.Errorf("scale: QuietRatio must be in [0,1], got %v", opts.QuietRatio)
	}
	if opts.QuietRatio > 0 && opts.QuietScenarioPath == "" {
		return Report{}, errors.New("scale: QuietScenarioPath is required when QuietRatio > 0")
	}
	if opts.QuietRatio < 1 && len(opts.ActiveScenarioPaths) == 0 {
		return Report{}, errors.New("scale: ActiveScenarioPaths is required when QuietRatio < 1")
	}

	quiet, active, err := loadScenarios(opts)
	if err != nil {
		return Report{}, err
	}

	httpClient := buildHTTPClient(opts.AllowInsecureTLS)
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
		hosts[i] = st
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Duration)
	defer cancel()

	g, runCtx := errgroup.WithContext(runCtx)
	for _, h := range hosts {
		g.Go(func() error {
			h.run(runCtx, opts.ServerURL, opts.EnrollSecret, httpClient)
			return nil
		})
	}
	_ = g.Wait()

	rep.EndTime = time.Now()
	rep.Duration = rep.EndTime.Sub(rep.StartTime)
	aggregate(&rep, hosts, opts)
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
func (h *hostState) run(ctx context.Context, serverURL, enrollSecret string, client *http.Client) {
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
		err := h.scenario.PostDirect(ctx, serverURL, token,
			fakeagent.WithHostID(h.hostID),
			fakeagent.WithStartTime(start),
			fakeagent.WithHTTPClient(client),
		)
		latency := time.Since(start)
		h.mu.Lock()
		if err != nil {
			h.errorCount++
			h.lastErr = err.Error()
		} else {
			h.latencies = append(h.latencies, latency)
			h.postedCount++
		}
		h.mu.Unlock()
		if err != nil && errors.Is(err, context.Canceled) {
			return
		}
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
	all := make([]time.Duration, 0, len(hosts)*16)
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
	// Nearest-rank method: rank index = ceil(p/100 * N) - 1, clamped to [0, N-1]. Matches the convention used by Prometheus
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
		return "", enrollRetry429Gap, errors.New("HTTP 429 from /api/enroll")
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
