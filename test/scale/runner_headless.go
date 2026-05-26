//go:build !windows && (!darwin || !cgo)

// Build tag (Copilot #277): the previous `!darwin || !cgo` tag included Windows, but this file implements ModeHeadless
// via unix-domain sockets (net.Listen / net.Dial "unix") which Windows doesn't support. Excluding windows here makes
// `runner_headless_unsupported.go` the live runHeadless on Windows, which returns a clear error rather than failing at
// runtime inside the dial. Linux + darwin-without-cgo are the only platforms where ModeHeadless is actually exercised
// today; the build tag now matches reality.
package scale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fleetdm/edr/agent/cmd/fleet-edr-agent-headless/headless"
	"github.com/fleetdm/edr/test/fakeagent"
)

// controlPlaneWaitTimeout caps the per-host wait for headless.Run's control plane to come up. The control plane is a unix
// socket bind which is fast (<10ms typical), but a heavily-loaded CI runner starting 100 headless agents at once can take
// seconds to schedule the goroutine. 5s is comfortably above observed startup time without leaving the scenario feeder
// blocked indefinitely if the headless agent fails to start.
const controlPlaneWaitTimeout = 5 * time.Second

// runHeadless is the ModeHeadless implementation of Run. Each simulated host gets its own headless.Run + SQLite queue +
// control-plane socket; a background poller samples GET /state every QueueDepthPollInterval; a scenario feeder loops
// FeedControlPlane until the run window closes. Returns a Report with the v2 queue-depth fields populated alongside the
// shared latency fields.
func runHeadless(ctx context.Context, opts Options) (Report, error) {
	quiet, active, err := loadScenarios(opts)
	if err != nil {
		return Report{}, err
	}

	httpClient := buildHTTPClient(opts.AllowInsecureTLS)
	rep := Report{
		StartTime:         time.Now(),
		Mode:              ModeHeadless,
		HostCount:         opts.HostCount,
		PassP99:           opts.PassP99,
		PassMaxQueueDepth: opts.PassMaxQueueDepth,
		PerHost:           make([]HostReport, opts.HostCount),
	}

	hosts, setupErrs := setupHeadlessHosts(ctx, opts, httpClient, quiet, active, &rep)
	defer cleanupHeadlessHosts(hosts)

	runCtx, cancel := context.WithTimeout(ctx, opts.Duration)
	defer cancel()

	var wg sync.WaitGroup
	for i, h := range hosts {
		if h == nil {
			rep.PerHost[i] = HostReport{
				HostID:     "(setup-failed)",
				LastError:  setupErrs[i].Error(),
				ErrorCount: 1,
			}
			continue
		}
		wg.Add(1)
		go func(h *headlessHostState) {
			defer wg.Done()
			h.run(ctx, runCtx, opts, httpClient)
		}(h)
	}
	wg.Wait()

	rep.EndTime = time.Now()
	rep.Duration = rep.EndTime.Sub(rep.StartTime)
	aggregateHeadless(&rep, hosts, opts)

	if opts.SigNozURL != "" {
		p99, qErr := querySigNozServerP99(ctx, opts.SigNozURL, rep.StartTime, rep.EndTime)
		if qErr != nil {
			rep.SigNozQueryError = qErr.Error()
		} else {
			rep.ServerLatencyP99 = &p99
			if rep.LatencyP99 > 0 {
				delta := rep.LatencyP99 - p99
				rep.ClientServerDeltaP99 = &delta
			}
		}
	}

	return rep, ctx.Err()
}

// headlessHostState is the per-host setup + runtime state. setup populates hostID/token/temp paths/scenario; run owns the
// goroutines that drive headless.Run, scenario feeder, and /state poller; aggregateHeadless reads the post-run fields.
type headlessHostState struct {
	index        int
	hostID       string
	token        string
	tempDir      string
	queuePath    string
	socketPath   string
	scenario     *fakeagent.Scenario
	scenarioName string
	gap          time.Duration

	mu                sync.Mutex
	errorCount        int
	lastErr           string
	queueDepthSamples []int64
	queueDepthMax     int64
	eventsInjected    int64
	injectErrors      int64
}

// setupHeadlessHosts builds every per-host state in parallel: enroll, allocate temp dir, assign scenario. Setup failures land
// in setupErrs[i] and the hosts[i] slot is nil; the caller fills the PerHost slot with the setup-error message. Bounded
// parallelism keeps the enroll fan-out under the server's per-IP rate limiter.
func setupHeadlessHosts(
	ctx context.Context, opts Options, httpClient *http.Client,
	quiet *fakeagent.Scenario, active []*fakeagent.Scenario, rep *Report,
) ([]*headlessHostState, []error) {
	hosts := make([]*headlessHostState, opts.HostCount)
	setupErrs := make([]error, opts.HostCount)
	quietCutoff := int(float64(opts.HostCount) * opts.QuietRatio)

	// Setup uses the parent context directly. enrollOne retries 3x at most ~1.5s; with the 32-way semaphore below a
	// 100-host setup completes in well under 10s on a healthy server. The caller bounds setup by passing a context with
	// a deadline if needed (the scaledriver CLI uses signal.NotifyContext, not a deadline).
	setupCtx := ctx

	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	var counterMu sync.Mutex
	for i := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			st := buildHostState(i, quietCutoff, opts, quiet, active, &counterMu, rep)
			if err := enrollAndAllocate(setupCtx, st, opts, httpClient); err != nil {
				setupErrs[i] = err
				cleanupHostDir(st)
				return
			}
			hosts[i] = st
		}(i)
	}
	wg.Wait()
	return hosts, setupErrs
}

// buildHostState allocates the per-host bookkeeping struct + assigns the scenario from the quiet/active pools. The counter
// update for QuietHostCount + ActiveHostCount is guarded so concurrent setup goroutines don't race the Report fields.
func buildHostState(
	i, quietCutoff int, opts Options, quiet *fakeagent.Scenario, active []*fakeagent.Scenario,
	counterMu *sync.Mutex, rep *Report,
) *headlessHostState {
	st := &headlessHostState{
		index:  i,
		hostID: uuid.NewString(),
	}
	counterMu.Lock()
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
	counterMu.Unlock()
	return st
}

// enrollAndAllocate runs the per-host setup IO: enroll over HTTP, create temp dir for the SQLite WAL + control-plane
// socket. The temp dir uses an "edrs" prefix kept short so the unix socket path fits AF_UNIX's 104-byte sun_path ceiling
// on macOS dev boxes (Linux's limit is 108 bytes but the macOS constraint is the tighter one).
//
// Each host's enroll is preceded by a staggered sleep so 100 hosts don't pile up at /api/enroll's per-IP rate limiter at
// once (same defense the direct-mode hostState.run uses; see staggeredEnrollStart's comment for the math + history).
func enrollAndAllocate(ctx context.Context, st *headlessHostState, opts Options, httpClient *http.Client) error {
	if err := staggeredEnrollStart(ctx, st.index, opts.HostCount); err != nil {
		return fmt.Errorf("enroll stagger: %w", err)
	}
	token, err := enrollOne(ctx, httpClient, opts.ServerURL, opts.EnrollSecret, st.hostID)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	st.token = token
	dir, err := os.MkdirTemp("", "edrs")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	st.tempDir = dir
	st.queuePath = filepath.Join(dir, "q.db")
	st.socketPath = filepath.Join(dir, "c.sock")
	return nil
}

// cleanupHostDir removes a single host's temp dir. Called both on setup-failure (so failed slots don't leak) and on a
// successful run's teardown via cleanupHeadlessHosts.
func cleanupHostDir(st *headlessHostState) {
	if st == nil || st.tempDir == "" {
		return
	}
	_ = os.RemoveAll(st.tempDir)
}

// cleanupHeadlessHosts removes every per-host temp dir at the end of a run. Called via defer so a panic mid-run still
// reclaims disk space.
func cleanupHeadlessHosts(hosts []*headlessHostState) {
	for _, h := range hosts {
		cleanupHostDir(h)
	}
}

// run drives one simulated host's runtime: spawn headless.Run, wait for control plane up, start /state poller, loop
// scenario feeder until runCtx done. Errors from individual goroutines accumulate into the host state (lastErr,
// errorCount) but do not abort the host's loop - per-host robustness mirrors the v1 direct-mode behaviour.
//
// Two-context lifecycle:
//
//	parentCtx: outlives the run window. The headless agent uses this so the control plane stays listening past runCtx's
//	  expiry, just long enough for finalStateSnapshot to read /state one last time.
//	runCtx:    bounded by opts.Duration. The scenario feeder + /state poller use this so they stop at the run boundary.
//
// Without this split the run window's expiry tears down the control-plane socket before finalStateSnapshot can read it,
// and the post-run events_injected counter lands as 0.
func (h *headlessHostState) run(parentCtx, runCtx context.Context, opts Options, httpClient *http.Client) {
	agentCtx, agentCancel := context.WithCancel(parentCtx)
	defer agentCancel()

	headlessDone := make(chan error, 1)
	go func() {
		headlessDone <- headless.Run(agentCtx, headless.Options{
			ServerURL:     opts.ServerURL,
			HostID:        h.hostID,
			QueuePath:     h.queuePath,
			SocketPath:    h.socketPath,
			TokenProvider: &scaleTokenProvider{token: h.token, hostID: h.hostID},
			HTTPClient:    httpClient,
			Logger:        slog.Default(),
		})
	}()

	if err := waitForControlPlane(agentCtx, h.socketPath); err != nil {
		h.recordErr("control plane up: " + err.Error())
		agentCancel()
		<-headlessDone
		return
	}

	pollerDone := make(chan struct{})
	go func() {
		defer close(pollerDone)
		h.pollState(runCtx, opts.QueueDepthPollInterval)
	}()

	rng := rand.New(rand.NewSource(hashSeed(h.hostID))) //nolint:gosec // jitter, not security
	for runCtx.Err() == nil {
		// WithHostID overrides the scenario's baked-in host.id so every emitted envelope's host_id matches the bearer
		// token the agent presents on /api/events. Without this override the server's host_id_mismatch validator
		// rejects the upload with HTTP 400 and the events stay queued until the quarantine threshold fires.
		feedErr := h.scenario.FeedControlPlane(runCtx, h.socketPath, fakeagent.WithHostID(h.hostID))
		if feedErr != nil && runCtx.Err() == nil {
			h.recordErr("feed: " + feedErr.Error())
		}
		jittered := time.Duration(float64(h.gap) * (jitterFloor + jitterRange*rng.Float64()))
		if err := sleepCtx(runCtx, jittered); err != nil {
			break
		}
	}

	// runCtx is now done, but agentCtx is still alive (parentCtx outlives the run window). The control plane is still
	// listening, so this final /state read captures the actual end-of-run events_injected + inject_errors counters.
	h.finalStateSnapshot(agentCtx)

	agentCancel()
	<-pollerDone
	<-headlessDone
}

// recordErr is the host-level error sink. Mirrors v1's hostState.recordErr but keeps the headlessHostState type isolated.
func (h *headlessHostState) recordErr(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errorCount++
	h.lastErr = msg
}

// pollState loops on a ticker, calling GET /state via the host's unix socket on each tick and recording queue_depth. A
// failed poll bumps the host's errorCount; the loop continues so a transient socket hiccup doesn't lose subsequent samples.
func (h *headlessHostState) pollState(ctx context.Context, interval time.Duration) {
	client := unixSocketHTTPClient(h.socketPath)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state, err := readControlState(ctx, client, h.socketPath)
			if err != nil {
				// Guard against false-positive error counts at end-of-run: when runCtx expires the in-flight readControlState
				// returns context.Canceled. Recording that as a poll error would inflate Report.ErrorCount and flip Pass
				// to false (Gemini #277). Only record when the context is still live - a real /state failure mid-run.
				if ctx.Err() == nil {
					h.recordErr("poll /state: " + err.Error())
				}
				continue
			}
			h.mu.Lock()
			h.queueDepthSamples = append(h.queueDepthSamples, state.QueueDepth)
			if state.QueueDepth > h.queueDepthMax {
				h.queueDepthMax = state.QueueDepth
			}
			h.mu.Unlock()
		}
	}
}

// finalStateSnapshot reads /state once after the scenario feeder exits so the report carries the end-of-run events_injected
// and inject_errors counters (the live counter values; the poller's last sample may have been seconds ago). A failed read
// is logged via recordErr but does not abort - aggregation reports the per-host fields it has.
func (h *headlessHostState) finalStateSnapshot(ctx context.Context) {
	client := unixSocketHTTPClient(h.socketPath)
	state, err := readControlState(ctx, client, h.socketPath)
	if err != nil {
		h.recordErr("final /state: " + err.Error())
		return
	}
	h.mu.Lock()
	h.eventsInjected = state.EventsInjected
	h.injectErrors = state.InjectErrors
	h.mu.Unlock()
}

// scaleTokenProvider is the headless.Options TokenProvider implementation for scale runs. Fixed values: enrollOne ran once
// per host during setup and produced the bearer token; the uploader presents that token on every /api/events POST. A 401
// from the server in headless mode is a setup/test bug, not a re-enroll trigger, so OnUnauthorized is a no-op.
type scaleTokenProvider struct {
	token  string
	hostID string
}

func (s *scaleTokenProvider) Token() string  { return s.token }
func (s *scaleTokenProvider) HostID() string { return s.hostID }

// OnUnauthorized is intentionally a no-op in scale runs: a 401 from the server in headless mode is a setup/test bug
// (mismatched enroll secret, server-side token revoke), not a re-enroll trigger. The scale runner aborts the host on
// any persistent error path through the uploader's quarantine; the per-host LastError captures the diagnostic and the
// run's pass gate flips. Sonar S1186 fix - explicit no-op comment per the rule (#277).
func (s *scaleTokenProvider) OnUnauthorized(_ context.Context) {}

func (s *scaleTokenProvider) Rotate(_ context.Context, _ string) error { return nil }

// controlState mirrors the headless package's stateResponse so the scale runner can parse /state without importing the
// unexported type. Field tags match the wire format the control plane emits.
type controlState struct {
	EventsInjected   int64 `json:"events_injected"`
	InjectErrors     int64 `json:"inject_errors"`
	LastInjectAtUnix int64 `json:"last_inject_at_unix"`
	QueueDepth       int64 `json:"queue_depth"`
}

// readControlState issues GET http://unix/state via the provided client and decodes the response into controlState. The
// client must already be configured to dial the host's unix socket (see unixSocketHTTPClient).
func readControlState(ctx context.Context, client *http.Client, socketPath string) (controlState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/state", nil)
	if err != nil {
		return controlState{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return controlState{}, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return controlState{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return controlState{}, fmt.Errorf("/state HTTP %d: %s", resp.StatusCode, string(body))
	}
	var state controlState
	if err := json.Unmarshal(body, &state); err != nil {
		return controlState{}, fmt.Errorf("decode /state: %w", err)
	}
	return state, nil
}

// unixSocketHTTPClient builds an HTTP client whose Transport dials the host's unix socket. The "host" portion of any URL
// the client sees is ignored - net.Dialer in the Transport overrides the network/addr. A short Timeout keeps a hung
// control plane from blocking the runner's wall clock; the call sites use parent context for cancellation too.
//
// DisableKeepAlives is true so each /state poll closes its connection immediately. Without this, the per-host poller
// keeps a unix-socket FD open across the QueueDepthPollInterval ticks; at 100 hosts that's 100 idle FDs sitting in the
// Transport's idle-conn pool, and the poller is the dominant FD-consuming code path. Closing per-call keeps the
// headless lane comfortably under the ulimit budget (Gemini #277).
func unixSocketHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// waitForControlPlane polls the unix socket until either GET /state returns 200 (control plane is up) or
// controlPlaneWaitTimeout expires. The first iteration usually fires before the socket file exists; the loop swallows
// connection-refused errors and retries every 50ms.
func waitForControlPlane(ctx context.Context, socketPath string) error {
	waitCtx, cancel := context.WithTimeout(ctx, controlPlaneWaitTimeout)
	defer cancel()
	client := unixSocketHTTPClient(socketPath)
	tick := 50 * time.Millisecond
	for waitCtx.Err() == nil {
		_, err := readControlState(waitCtx, client, socketPath)
		if err == nil {
			return nil
		}
		if err := sleepCtx(waitCtx, tick); err != nil {
			break
		}
	}
	return errors.New("control plane did not respond within " + controlPlaneWaitTimeout.String())
}

// aggregateHeadless folds per-host queue-depth samples + events_injected counters into the Report. Latency fields stay 0
// in headless mode (the agent path makes client-observed per-envelope latency meaningless; the SigNoz cross-check is the
// honest latency signal). PassMaxQueueDepth, when > 0, gates the run.
func aggregateHeadless(rep *Report, hosts []*headlessHostState, opts Options) {
	allDepths := make([]int64, 0, len(hosts)*8)
	for i, h := range hosts {
		if h == nil {
			continue
		}
		h.mu.Lock()
		hr := HostReport{
			HostID:         h.hostID,
			Scenario:       h.scenarioName,
			ErrorCount:     h.errorCount,
			LastError:      h.lastErr,
			EventsInjected: h.eventsInjected,
			InjectErrors:   h.injectErrors,
			QueueDepthMax:  h.queueDepthMax,
		}
		// ObservationCount in headless mode = total injected envelopes (the equivalent unit of work to v1's per-envelope POST).
		hr.ObservationCount = int(h.eventsInjected)
		rep.PerHost[i] = hr
		rep.ObservationCount += hr.ObservationCount
		rep.ErrorCount += hr.ErrorCount
		allDepths = append(allDepths, h.queueDepthSamples...)
		h.mu.Unlock()
	}

	rep.QueueDepthSamples = len(allDepths)
	if len(allDepths) > 0 {
		sortedDepths := slices.Clone(allDepths)
		slices.Sort(sortedDepths)
		rep.QueueDepthP50 = depthPercentile(sortedDepths, percentileP50)
		rep.QueueDepthP95 = depthPercentile(sortedDepths, percentileP95)
		rep.QueueDepthP99 = depthPercentile(sortedDepths, percentileP99)
		rep.QueueDepthMax = sortedDepths[len(sortedDepths)-1]
	}

	if rep.Duration > 0 {
		rep.ObservationsPerSec = float64(rep.ObservationCount) / rep.Duration.Seconds()
	}

	rep.Pass = true
	if rep.ErrorCount > 0 {
		rep.Pass = false
		rep.FailReasons = append(rep.FailReasons, fmt.Sprintf("error_count > 0 (got %d)", rep.ErrorCount))
	}
	if rep.ObservationCount == 0 {
		rep.Pass = false
		rep.FailReasons = append(rep.FailReasons, "observation_count is zero")
	}
	if opts.PassMaxQueueDepth > 0 && rep.QueueDepthMax > opts.PassMaxQueueDepth {
		rep.Pass = false
		rep.FailReasons = append(rep.FailReasons,
			fmt.Sprintf("queue_depth_max %d exceeds budget %d", rep.QueueDepthMax, opts.PassMaxQueueDepth))
	}
}

// depthPercentile is the int64 analogue of percentileSorted (which operates on time.Duration). Same nearest-rank method;
// same banker's-style rounding constant. Returns 0 for an empty input.
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
