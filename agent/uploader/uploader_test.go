package uploader

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fleetdm/edr/agent/queue"
)

func TestUploadBatch(t *testing.T) {
	q := openTestQueue(t)

	events := []string{
		`{"event_id":"aaa","event_type":"exec"}`,
		`{"event_id":"bbb","event_type":"fork"}`,
	}
	for _, e := range events {
		if err := q.Enqueue([]byte(e)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	var received []json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events" {
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
	cfg.APIKey = "test-key"
	cfg.BatchSize = 10

	u := New(q, cfg)
	u.drainOnce(t.Context())

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}

	// Verify events were marked as uploaded.
	depth, _ := q.Depth()
	if depth != 0 {
		t.Fatalf("expected queue depth 0 after upload, got %d", depth)
	}
}

func TestUploadRetry(t *testing.T) {
	q := openTestQueue(t)

	if err := q.Enqueue([]byte(`{"event_id":"retry-test"}`)); err != nil {
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

	u := New(q, cfg)
	u.drainOnce(t.Context())

	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}

	depth, _ := q.Depth()
	if depth != 0 {
		t.Fatalf("expected queue depth 0 after retry success, got %d", depth)
	}
}

func TestUploadAllRetriesFail(t *testing.T) {
	q := openTestQueue(t)

	if err := q.Enqueue([]byte(`{"event_id":"fail-test"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.MaxRetries = 3

	u := New(q, cfg)
	u.drainOnce(t.Context())

	// Event should still be in queue since upload failed.
	depth, _ := q.Depth()
	if depth != 1 {
		t.Fatalf("expected queue depth 1 after failed upload, got %d", depth)
	}
}

func openTestQueue(t *testing.T) *queue.Queue {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	q, err := queue.Open(dbPath)
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}

func init() {
	// Suppress log output in tests.
	_ = time.Now
}
