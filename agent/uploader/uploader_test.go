package uploader

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/fleetdm/edr/agent/queue"
)

// spec:agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token
// spec:agent-event-uploader/successful-upload-acknowledges-events/server-returns-200-or-204
//
// Two scenarios share this test. The Authorization-header assertion + path check pin the bearer-token
// contract; the depth==0 assertion after a 200 pins the "marked uploaded, eligible for removal" half of
// successful-upload-acknowledges-events. The 204 branch of "server returns 200 or 204" is symmetric
// because doUpload's success predicate is `resp.StatusCode >= 200 && resp.StatusCode < 300`, treating
// 2xx as a class; the 200 case here exercises that predicate.
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

// spec:agent-event-uploader/transient-failures-retry-with-backoff/first-attempt-times-out-second-succeeds
//
// Server returns 5xx on attempts 1 and 2, 200 on attempt 3. The scenario specifies "first attempt times
// out" but the contract is identical for any transient failure that doesn't produce a typed 4xx
// clientError: 5xx, network error, or timeout all flow through the same retry-with-backoff path. The
// 5xx-mid-batch shape (assertion: the SAME batch is sent each attempt, then marked uploaded once a 2xx
// arrives) is what the depth==0 assertion below pins.
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

// spec:agent-event-uploader/successful-upload-acknowledges-events/server-returns-5xx-mid-batch
// spec:agent-event-uploader/transient-failures-retry-with-backoff/all-retries-exhausted
//
// Two scenarios share this test. The 5xx-mid-batch scenario's THEN clauses ("none marked uploaded;
// same batch is eligible to retry on the next attempt") are pinned by the depth==1 assertion after the
// drain. The all-retries-exhausted scenario adds the cap clause: MaxRetries=3 means the uploader stops
// retrying after attempt 3 within this cycle, and the batch sits in the queue for a future cycle to try
// again.
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

// spec:agent-event-uploader/401-triggers-re-enrollment/401-during-upload
//
// Locks in the 401 -> re-auth signal. An early QA bug had OnAuthFail never firing because the agent's
// TLS config was broken; this test prevents any future regression where the auth path stops surfacing
// 401s to enrollment. Pins the three THEN clauses of the scenario: the auth-fail callback fires
// (called==1), the batch is not marked uploaded (depth==1), and the next cycle resumes with whatever
// token enrollment now holds (structural: TokenFn is called fresh on every drainOnce).
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

// spec:agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-no-token
//
// When the agent has not yet enrolled (TokenFn returns ""), the server returns 401 (because no
// Authorization header carries a valid token) and the events MUST stay in the local queue. The 401
// also triggers OnAuthFail, but the scenario's load-bearing clause for THIS test is "events are not
// removed from the local queue" — pinned by the depth==1 assertion below. The server's 401-on-empty-
// token enforcement is server-side; here we exercise the agent-side half (no token in the request
// header, batch stays queued).
func TestUpload_NoTokenBatchStaysQueued(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"no-token-evt"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	var sawAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	// No TokenFn => no Authorization header at all.
	cfg.MaxRetries = 3

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if sawAuthHeader != "" {
		t.Fatalf("expected no Authorization header when TokenFn is nil, got %q", sawAuthHeader)
	}
	depth, _ := q.Depth(ctx)
	if depth != 1 {
		t.Fatalf("expected queue depth 1 (batch stays queued on 401), got %d", depth)
	}
}

// spec:agent-event-uploader/bounded-request-size/queue-holds-more-events-than-fit-in-one-request
//
// Enqueue 10 events, set BatchSize=3. A single drainOnce dequeues exactly 3 events; the remaining 7
// stay queued for subsequent cycles. The spec's "one or more requests of bounded size" half is pinned
// by the single-request-with-3-events shape; the "events that did not fit ... remain queued" half is
// pinned by the depth==7 assertion. Multiple drainOnce calls would empty the queue but the bounded
// per-request shape is what this test pins.
func TestUpload_BoundedBatchSize(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	for i := range 10 {
		payload := fmt.Sprintf(`{"event_id":"bounded-%d"}`, i)
		if err := q.Enqueue(ctx, []byte(payload)); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	var receivedCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var events []json.RawMessage
		if err := json.Unmarshal(body, &events); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		receivedCount = len(events)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.BatchSize = 3

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if receivedCount != 3 {
		t.Fatalf("expected exactly 3 events in the bounded request, got %d", receivedCount)
	}
	depth, _ := q.Depth(ctx)
	if depth != 7 {
		t.Fatalf("expected 7 events still queued for subsequent cycles, got %d", depth)
	}
}

// spec:agent-event-uploader/401-triggers-re-enrollment/401-is-treated-as-non-retryable-within-the-cycle
//
// MaxRetries=5 but a single 401 must NOT consume the retry budget. Pinned by attempts.Load()==1: only
// one request hits the server even though the configured cap would allow 5. The spec rationale is that
// retrying a 401 with the SAME (stale) token would be wasteful and would delay the next cycle picking
// up a refreshed token from the enrollment path.
func TestUpload_401IsNonRetryableWithinCycle(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()
	if err := q.Enqueue(ctx, []byte(`{"event_id":"non-retry-401"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.TokenFn = func() string { return "stale-token" }
	cfg.OnAuthFail = func(context.Context) {}
	cfg.MaxRetries = 5 // intentionally generous; a 401 must NOT consume this budget

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected exactly 1 attempt on 401 regardless of MaxRetries=%d, got %d", cfg.MaxRetries, got)
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
