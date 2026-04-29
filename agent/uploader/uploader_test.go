package uploader

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/fleetdm/edr/agent/queue"
)

func TestUploadBatch(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	events := []string{
		`{"event_id":"aaa","event_type":"exec"}`,
		`{"event_id":"bbb","event_type":"fork"}`,
	}
	for _, e := range events {
		if err := q.Enqueue(ctx, []byte(e)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	var received []json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing or wrong auth header: %s", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.TokenFn = func() string { return "test-key" }
	cfg.BatchSize = 10

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}

	// Verify events were marked as uploaded.
	depth, _ := q.Depth(ctx)
	if depth != 0 {
		t.Fatalf("expected queue depth 0 after upload, got %d", depth)
	}
}

func TestUploadRetry(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"retry-test"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.MaxRetries = 5

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}

	depth, _ := q.Depth(ctx)
	if depth != 0 {
		t.Fatalf("expected queue depth 0 after retry success, got %d", depth)
	}
}

func TestUploadAllRetriesFail(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"fail-test"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.MaxRetries = 3

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	// Event should still be in queue since upload failed.
	depth, _ := q.Depth(ctx)
	if depth != 1 {
		t.Fatalf("expected queue depth 1 after failed upload, got %d", depth)
	}
}

// TestUpload401_CallsOnAuthFail locks in the 401 → re-auth signal. The Phase 1 QA bug was
// that OnAuthFail never fired because the agent's TLS config was broken; this test prevents
// any future regression where the auth path stops surfacing 401s to enrollment.
func TestUpload401_CallsOnAuthFail(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"x"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer srv.Close()

	var called atomic.Int64
	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.TokenFn = func() string { return "stale-token" }
	cfg.OnAuthFail = func(context.Context) { called.Add(1) }
	cfg.MaxRetries = 1

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if called.Load() != 1 {
		t.Fatalf("expected OnAuthFail to fire exactly once on 401, got %d", called.Load())
	}
	// Batch must stay in the queue so the next tick can retry with a fresh token.
	depth, _ := q.Depth(ctx)
	if depth != 1 {
		t.Fatalf("expected queue depth 1 after 401, got %d", depth)
	}
}

func openTestQueue(t *testing.T) *queue.Queue {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	q, err := queue.Open(t.Context(), dbPath, queue.Options{})
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}
