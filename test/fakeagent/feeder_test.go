package fakeagent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortSocketPath returns a unix-socket path short enough to satisfy macOS's 104-byte sun_path limit. t.TempDir embeds the test
// name, which puts long test names over the limit; this helper deliberately bypasses t.TempDir by using os.MkdirTemp with a short
// prefix so the resulting socket path fits the kernel limit.
//
//nolint:usetesting // t.TempDir would emit paths longer than AF_UNIX's 104-byte sun_path limit on macOS.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fa")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

// stubControlPlane is a minimal mock of the M2 headless binary's POST /event handler. It records every body it sees so the test can
// assert on FeedControlPlane's output without spinning up the real headless binary (that's M4's integration test, not M3's).
type stubControlPlane struct {
	server *http.Server
	socket string
	bodies [][]byte
	mu     sync.Mutex
	wg     sync.WaitGroup
}

func newStubControlPlane(t *testing.T) *stubControlPlane {
	t.Helper()
	socket := shortSocketPath(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	require.NoError(t, err)

	sp := &stubControlPlane{socket: socket}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /event", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sp.mu.Lock()
		sp.bodies = append(sp.bodies, body)
		sp.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
	sp.server = &http.Server{Handler: mux, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	sp.wg.Go(func() {
		_ = sp.server.Serve(listener)
	})
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = sp.server.Shutdown(shutdownCtx)
		sp.wg.Wait()
	})
	return sp
}

func (sp *stubControlPlane) received() [][]byte {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	out := make([][]byte, len(sp.bodies))
	copy(out, sp.bodies)
	return out
}

func TestFeedControlPlane_RoundTrip(t *testing.T) {
	sp := newStubControlPlane(t)

	s, err := LoadScenario("scenarios/exec-fork-exit.yaml")
	require.NoError(t, err)

	start := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	require.NoError(t, s.FeedControlPlane(t.Context(), sp.socket,
		WithStartTime(start), WithIDGenerator(seqID())))

	bodies := sp.received()
	require.Len(t, bodies, 3, "stub control plane should have received 3 envelopes")

	// Round-trip the first body and assert on shape: it's the fork event.
	var first Envelope
	require.NoError(t, json.Unmarshal(bodies[0], &first))
	assert.Equal(t, "fork", first.EventType)
	assert.Equal(t, "AAAA0002-0000-0000-0000-000000000002", first.HostID)
	assert.Equal(t, "e-0", first.EventID)
	assert.Equal(t, start.UnixNano(), first.TimestampNs)

	var forkPayload struct{ ChildPID, ParentPID int }
	// Payload is json.RawMessage in Envelope; unmarshal with the lowercase JSON tags via a quick re-decode.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(bodies[0], &raw))
	require.NoError(t, json.Unmarshal(raw["payload"], &struct {
		ChildPID  *int `json:"child_pid"`
		ParentPID *int `json:"parent_pid"`
	}{&forkPayload.ChildPID, &forkPayload.ParentPID}))
	assert.Equal(t, 4001, forkPayload.ChildPID)
	assert.Equal(t, 1, forkPayload.ParentPID)
}

func TestFeedControlPlane_PropagatesServerError(t *testing.T) {
	// A stub that always 500s: FeedControlPlane should return the error from the FIRST envelope and not call subsequent envelopes.
	socket := shortSocketPath(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	require.NoError(t, err)
	var attempts atomic.Int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}),
		ReadTimeout: time.Second, WriteTimeout: time.Second,
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	s, err := LoadScenario("scenarios/exec-fork-exit.yaml") // 3 events
	require.NoError(t, err)
	err = s.FeedControlPlane(t.Context(), socket, WithStartTime(time.Unix(0, 0)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
	assert.Equal(t, int32(1), attempts.Load(), "subsequent envelopes must not be sent after an error")
}

func TestFeedControlPlane_RespectsContextCancel(t *testing.T) {
	sp := newStubControlPlane(t)
	s, err := LoadScenario("scenarios/exec-fork-exit.yaml")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // pre-cancel
	err = s.FeedControlPlane(ctx, sp.socket, WithStartTime(time.Unix(0, 0)),
		WithSpeed(0.001)) // very slow playback so cancel beats the loop
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestPostDirect_RoundTrip(t *testing.T) {
	var (
		received       [][]byte
		mu             sync.Mutex
		seenAuthHeader string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Lock around BOTH writes - go test -race reports the unsynchronised seenAuthHeader write otherwise.
		mu.Lock()
		seenAuthHeader = r.Header.Get("Authorization")
		received = append(received, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	s, err := LoadScenario("scenarios/dns-and-network.yaml")
	require.NoError(t, err)
	require.NoError(t, s.PostDirect(t.Context(), srv.URL, "test-token", WithBatchSize(10)))

	mu.Lock()
	gotAuth := seenAuthHeader
	require.Len(t, received, 1, "BatchSize=10 should fit both events in one POST")
	firstBody := append([]byte(nil), received[0]...)
	mu.Unlock()
	assert.Equal(t, "Bearer test-token", gotAuth)

	var batch []Envelope
	require.NoError(t, json.Unmarshal(firstBody, &batch))
	require.Len(t, batch, 2)
	assert.Equal(t, "dns_query", batch[0].EventType)
	assert.Equal(t, "network_connect", batch[1].EventType)
}

func TestPostDirect_BatchesAcrossMultipleRequests(t *testing.T) {
	var batchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		batchCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	s, err := LoadScenario("scenarios/exec-fork-exit.yaml") // 3 events
	require.NoError(t, err)
	require.NoError(t, s.PostDirect(t.Context(), srv.URL, "tok", WithBatchSize(2)))
	assert.Equal(t, int32(2), batchCount.Load(), "3 events at batch_size=2 should split into 2 POSTs")
}

func TestPostDirect_PropagatesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	s, err := LoadScenario("scenarios/exec-fork-exit.yaml")
	require.NoError(t, err)
	err = s.PostDirect(t.Context(), srv.URL, "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}
