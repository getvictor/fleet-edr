//go:build integration && (!darwin || !cgo)

// Package agentserver is the UAT plan layer-3 (L3) integration test: a full real EDR server (via the M1-M3 production wiring composed
// by test/integration.Setup), the real M2 headless agent (via the agent/cmd/fleet-edr-agent-headless/headless package, in-process so
// the test doesn't pay subprocess startup), and the M3 fakeagent library driving each starter scenario through the agent's POST /event
// control plane. The pipeline under test is: scenario YAML -> fakeagent envelopes -> headless control plane -> stub receiver ->
// pumpEvents -> queue -> uploader -> /api/events -> detection processor -> events table -> ListHosts EventCount.
//
// One subtest per scenario in the starter corpus (M4 milestone: 5). Each subtest gets its own MySQL test database (testdb/full.Open
// via integration.Setup) so it can run with t.Parallel without cross-test interference.
//
// Build tag pairing: `integration` matches the existing test/integration suite gate; `!darwin || !cgo` matches the headless package's
// receiver-stub gate. CI's server-test job runs on ubuntu-latest where !darwin holds, so the suite picks these up automatically via
// `task test:go:server:integration`'s `./test/integration/...` glob. Darwin devs run with `CGO_ENABLED=0 task test:integration:agent-server`.
package agentserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/cmd/fleet-edr-agent-headless/headless"
	"github.com/fleetdm/edr/test/fakeagent"
	"github.com/fleetdm/edr/test/integration"
)

// scenarioCorpus is the M4 list. Paths are relative to this file so `go test` resolves them correctly under both `go test ./test/...`
// and direct `go test ./test/integration/agentserver/...` invocations.
var scenarioCorpus = []string{
	"../../fakeagent/scenarios/quiet-host.yaml",
	"../../fakeagent/scenarios/exec-fork-exit.yaml",
	"../../fakeagent/scenarios/dns-and-network.yaml",
	"../../fakeagent/scenarios/process-tree-deep.yaml",
	"../../fakeagent/scenarios/mixed-events.yaml",
}

func TestL3_HeadlessAgentToServer(t *testing.T) {
	// Subtests run SERIALLY rather than via t.Parallel. Each scenario stands up a fresh integration.Setup Stack which opens its own
	// MySQL pool (~4 connections via testdb.Open); five parallel Stacks on top of the rest of the integration suite's parallel test
	// load consistently push past MySQL's 500-connection ceiling (CI's bumped default) and cause Error 1040. Sequential keeps the
	// agentserver package's peak connection count to ~4 and the full-suite wall time barely changes since each subtest is sub-second.
	for _, path := range scenarioCorpus {
		t.Run(filepath.Base(path), func(t *testing.T) {
			runScenario(t, path)
		})
	}
}

// runScenario boots a fresh Stack, enrols a host using the scenario's host_id, spins headless.Run in a goroutine pointing at the
// Stack, drives the scenario via fakeagent.FeedControlPlane, and waits for the detection service to report EventCount >= len(timeline)
// for the host. The Eventually deadline is generous (10s) because the chain is queue.Open + uploader interval + server processor
// interval; the actual end-to-end latency is sub-second in practice but a slow CI runner can extend it.
func runScenario(t *testing.T, scenarioPath string) {
	t.Helper()

	scenario, err := fakeagent.LoadScenario(scenarioPath)
	require.NoError(t, err)

	stack := integration.Setup(t)
	hostID := scenario.Host.ID
	hostToken := enroll(t, stack, hostID)

	socketPath := shortSocketPath(t)
	opts := headless.Options{
		ServerURL: stack.Server.URL,
		HostID:    hostID,
		QueuePath: filepath.Join(t.TempDir(), "queue.db"),
		// UploadInterval is small so the uploader fires within the Eventually budget. BatchSize=100 fits any of the 5 scenarios in
		// a single batch (largest is 9 events).
		BatchSize:      100,
		UploadInterval: 50 * time.Millisecond,
		SocketPath:     socketPath,
		TokenProvider:  &stubTokenProvider{token: hostToken, hostID: hostID},
	}

	ctx, cancel := context.WithCancel(t.Context())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- headless.Run(ctx, opts) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runErrCh:
			if err != nil && !isContextCanceled(err) {
				t.Errorf("headless.Run returned non-cancel error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("headless.Run did not exit within 10s of ctx cancel")
		}
	})

	waitForControlPlane(t, socketPath)
	require.NoError(t, scenario.FeedControlPlane(ctx, socketPath))

	expected := int64(len(scenario.Timeline))
	require.Eventuallyf(t, func() bool {
		hosts, err := stack.DetectionService().ListHosts(ctx)
		if err != nil {
			return false
		}
		for _, h := range hosts {
			if h.HostID == hostID && h.EventCount >= expected {
				return true
			}
		}
		return false
	}, 10*time.Second, 100*time.Millisecond,
		"host %s never reached %d events through the agent pipeline", hostID, expected)
}

// enroll posts to /api/enroll with the integration test's pre-baked enroll secret and returns the issued host_token. The Setup helper
// in test/integration wires integration.EnrollSecret into the endpoint context, so this mirrors the test/integration/full_path_test
// pattern verbatim.
func enroll(t *testing.T, stack *integration.Stack, hostID string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"enroll_secret": integration.EnrollSecret,
		"hardware_uuid": hostID,
		"hostname":      "l3-agentserver.local",
		"agent_version": "l3-integration-test",
		"os_version":    "macOS 26.0",
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		stack.Server.URL+"/api/enroll", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equalf(t, http.StatusOK, resp.StatusCode, "POST /api/enroll status for %s", hostID)

	var er struct {
		HostID    string `json:"host_id"`
		HostToken string `json:"host_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&er))
	require.Equal(t, hostID, er.HostID)
	require.NotEmpty(t, er.HostToken, "enroll response must carry host_token")
	return er.HostToken
}

// waitForControlPlane polls the headless agent's GET /state until it returns 200 or the budget expires. Without this the test would
// race FeedControlPlane against the listener bind.
func waitForControlPlane(t *testing.T, socketPath string) {
	t.Helper()
	require.Eventuallyf(t, func() bool {
		client := unixHTTPClient(socketPath)
		resp, err := client.Get("http://unix/state")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "control plane at %s never came up", socketPath)
}

// stubTokenProvider implements enrollment.TokenProvider with fixed values so the integration test can skip the agent-side enrollment
// network call. The host_token here is the real token the server minted via /api/enroll above; the uploader's Authorization header
// gets it, the server's middleware accepts it, the event lands in the database.
type stubTokenProvider struct {
	token  string
	hostID string
}

func (s *stubTokenProvider) Token() string                            { return s.token }
func (s *stubTokenProvider) HostID() string                           { return s.hostID }
func (s *stubTokenProvider) OnUnauthorized(_ context.Context)         {}
func (s *stubTokenProvider) Rotate(_ context.Context, _ string) error { return nil }

// shortSocketPath returns a unix-socket path short enough to fit AF_UNIX's 104-byte sun_path limit on macOS. t.TempDir embeds the
// full test name which can easily exceed that limit; os.MkdirTemp with a short prefix keeps the path under the budget.
//
//nolint:usetesting // t.TempDir would emit paths longer than AF_UNIX's sun_path limit on macOS.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "as")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

// unixHTTPClient is a tiny http.Client that always dials the given unix socket. The "http://unix" URL host is a placeholder net/http
// requires; the connection goes to socketPath. Matches the same shape fakeagent uses internally.
func unixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// isContextCanceled tests for the typical shutdown-path error envelopes the headless pipeline produces. Plain context.Canceled doesn't
// always cover wrapped variants from the uploader or the queue.
func isContextCanceled(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return s == context.Canceled.Error() ||
		s == context.DeadlineExceeded.Error() ||
		// Wrapped variants surface as "... : context canceled" from the uploader / queue.
		bytes.Contains([]byte(s), []byte("context canceled"))
}
