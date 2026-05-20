//go:build !darwin || !cgo

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/receiver"
)

// stubTokenProvider implements enrollment.TokenProvider with fixed values. Tests construct one directly so they bypass the network
// enrollment flow; the headless binary's production main wires the real enrollment.Ensure result instead.
type stubTokenProvider struct {
	token  string
	hostID string
}

func (s *stubTokenProvider) Token() string                            { return s.token }
func (s *stubTokenProvider) HostID() string                           { return s.hostID }
func (s *stubTokenProvider) OnUnauthorized(_ context.Context)         {}
func (s *stubTokenProvider) Rotate(_ context.Context, _ string) error { return nil }

func TestOptionsValidate(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want string // substring of expected error; empty means success
	}{
		{
			name: "missing ServerURL",
			opts: Options{HostID: "h", QueuePath: "/q", TokenProvider: &stubTokenProvider{}},
			want: "ServerURL is required",
		},
		{
			name: "missing HostID",
			opts: Options{ServerURL: "http://x", QueuePath: "/q", TokenProvider: &stubTokenProvider{}},
			want: "HostID is required",
		},
		{
			name: "missing QueuePath",
			opts: Options{ServerURL: "http://x", HostID: "h", TokenProvider: &stubTokenProvider{}},
			want: "QueuePath is required",
		},
		{
			name: "missing TokenProvider",
			opts: Options{ServerURL: "http://x", HostID: "h", QueuePath: "/q"},
			want: "TokenProvider is required",
		},
		{
			name: "happy path fills defaults",
			opts: Options{ServerURL: "http://x", HostID: "h", QueuePath: "/q", TokenProvider: &stubTokenProvider{}},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.validate()
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, defaultBatchSize, tc.opts.BatchSize)
				assert.Equal(t, defaultUploadInterval, tc.opts.UploadInterval)
				assert.Equal(t, uploaderMaxRetries, tc.opts.UploaderMaxRetries)
				assert.NotNil(t, tc.opts.Logger)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.want)
			}
		})
	}
}

// TestHeadlessRoundTrip exercises the full happy path: control plane injects events, queue + uploader forwards them, fake EDR server
// receives them with the expected auth header. This is L3 (headless agent + server) compressed into a single in-process Go test; the
// real CI L3 job will reuse the same pattern with the headless binary launched as a subprocess.
func TestHeadlessRoundTrip(t *testing.T) {
	var (
		received       atomic.Int32
		capturedBodies [][]byte
		mu             sync.Mutex
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		capturedBodies = append(capturedBodies, body)
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ctl.sock")

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- Run(ctx, Options{
			ServerURL:      srv.URL,
			HostID:         "test-host-1",
			QueuePath:      filepath.Join(tmpDir, "queue.db"),
			SocketPath:     socketPath,
			TokenProvider:  &stubTokenProvider{token: "test-token", hostID: "test-host-1"},
			BatchSize:      5,
			UploadInterval: 50 * time.Millisecond,
		})
	}()

	// Wait for the control plane socket to accept connections. Eventually polls every 50ms up to 5s, which is plenty for goroutine
	// startup + net.Listen + the eventLoop's first iteration on a busy CI runner.
	require.Eventually(t, func() bool {
		resp, err := unixHTTPGet(socketPath, "/state")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "control plane never came up")

	// Inject 3 distinct events. The uploader's BatchSize=5 means they'll fly in a single batch.
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(
			`{"event_id":"e-%d","host_id":"test-host-1","event_type":"exec","timestamp_ns":%d}`,
			i, time.Now().UnixNano(),
		)
		resp, err := unixHTTPPost(socketPath, "/event", []byte(body))
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusAccepted, resp.StatusCode, "POST /event #%d", i)
	}

	// Wait for the uploader to drain. UploadInterval=50ms, so within 2s we expect the batch.
	require.Eventually(t, func() bool { return received.Load() > 0 }, 5*time.Second, 50*time.Millisecond,
		"no events received by fake server")
	mu.Lock()
	bodyCount := len(capturedBodies)
	mu.Unlock()
	assert.GreaterOrEqual(t, bodyCount, 1, "expected at least one upload batch")

	// /state should reflect the 3 injects and 0 inject errors.
	resp, err := unixHTTPGet(socketPath, "/state")
	require.NoError(t, err)
	stateBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var state stateResponse
	require.NoError(t, json.Unmarshal(stateBody, &state))
	assert.Equal(t, int64(3), state.EventsInjected)
	assert.Equal(t, int64(0), state.InjectErrors)

	// Clean shutdown. Run should exit within drainTimeout + a margin.
	cancel()
	select {
	case err := <-runErrCh:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not exit within 10s of ctx cancel")
	}
}

// TestControlPlaneErrorPaths exercises the POST /event handler's input validation branches. Driven through the real unix socket so the
// MaxBytesReader, json.Valid, and ServeMux pattern-matching are all exercised end-to-end.
func TestControlPlaneErrorPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ctl.sock")

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- Run(ctx, Options{
			ServerURL:      srv.URL,
			HostID:         "test-host-2",
			QueuePath:      filepath.Join(tmpDir, "queue.db"),
			SocketPath:     socketPath,
			TokenProvider:  &stubTokenProvider{token: "tok", hostID: "test-host-2"},
			BatchSize:      5,
			UploadInterval: 1 * time.Second, // slow so we don't race the test with uploads
		})
	}()

	require.Eventually(t, func() bool {
		resp, err := unixHTTPGet(socketPath, "/state")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)

	cases := []struct {
		name string
		body []byte
		want int
	}{
		{name: "empty body", body: nil, want: http.StatusBadRequest},
		{name: "invalid JSON", body: []byte("not json"), want: http.StatusBadRequest},
		{name: "valid JSON object", body: []byte(`{"event_id":"ok"}`), want: http.StatusAccepted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := unixHTTPPost(socketPath, "/event", tc.body)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}

	// 405 (method-not-allowed) for an unhandled verb is enforced by the ServeMux pattern; covers the "POST /event" specificity.
	resp, err := unixHTTPGet(socketPath, "/event")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	cancel()
	<-runErrCh
}

// unixHTTPGet performs an HTTP GET over a unix socket. Used by the test to talk to the control plane.
func unixHTTPGet(socketPath, path string) (*http.Response, error) {
	client := unixHTTPClient(socketPath)
	return client.Get("http://unix" + path)
}

// unixHTTPPost performs an HTTP POST over a unix socket with a raw body.
func unixHTTPPost(socketPath, path string, body []byte) (*http.Response, error) {
	client := unixHTTPClient(socketPath)
	return client.Post("http://unix"+path, "application/json", bytes.NewReader(body))
}

func unixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

// TestHandlePostEventBufferFull drives the buffer-full branch directly without standing up the whole pipeline. A receiver constructed
// with buffer size 0 always returns ErrBufferFull from Inject, so the very first POST exercises the 503 path.
func TestHandlePostEventBufferFull(t *testing.T) {
	recv := receiver.New("test", 0)
	cnt := &counters{}
	logger := slog.Default()

	req := httptest.NewRequest(http.MethodPost, "/event", bytes.NewReader([]byte(`{"event_id":"a"}`)))
	w := httptest.NewRecorder()

	handlePostEvent(w, req, recv, cnt, logger)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "buffer full")
	assert.Equal(t, int64(1), cnt.injectErrors.Load())
	assert.Equal(t, int64(0), cnt.eventsInjected.Load())
}

// TestHandlePostEventBodyTooLarge exercises the MaxBytesReader branch by feeding a body larger than maxEventBytes. The handler should
// reject with 400 and leave the receiver's counters untouched.
func TestHandlePostEventBodyTooLarge(t *testing.T) {
	recv := receiver.New("test", 1024)
	cnt := &counters{}
	logger := slog.Default()

	// 2 MiB body, well over the 1 MiB cap. The JSON shape doesn't matter; the size check fires before json.Valid.
	bigBody := strings.Repeat("a", 2*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(bigBody))
	w := httptest.NewRecorder()

	handlePostEvent(w, req, recv, cnt, logger)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, int64(0), cnt.eventsInjected.Load())
	assert.Equal(t, int64(0), cnt.injectErrors.Load())
}
