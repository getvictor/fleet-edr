package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
// When the agent has not yet enrolled and TokenFn returns "", the server returns 401 (no valid
// Authorization header) and the events MUST stay in the local queue. The 401 also triggers
// OnAuthFail, but the scenario's load-bearing clause for THIS test is "events are not removed from
// the local queue" pinned by the depth==1 assertion below. The server's 401-on-empty-token
// enforcement is server-side; here we exercise the agent-side half (no usable token in the request
// header, batch stays queued).
func TestUpload_NoTokenBatchStaysQueued(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"no-token-evt"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// atomic.Value because httptest hands requests on a separate goroutine; the bare assignment
	// would be a race under `go test -race`.
	var sawAuthHeader atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuthHeader.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	// TokenFn present but returns "" — the unenrolled-agent shape the spec scenario describes.
	cfg.TokenFn = func() string { return "" }
	cfg.MaxRetries = 3

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if got, ok := sawAuthHeader.Load().(string); ok && got != "" {
		t.Fatalf("expected no usable Authorization header when TokenFn returns \"\", got %q", got)
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

	// atomic.Int64 because the httptest handler runs on its own goroutine; a bare int would race
	// against the main-goroutine read after drainOnce. int64 avoids the gosec int->int32 overflow lint.
	var receivedCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		var events []json.RawMessage
		if err := json.Unmarshal(body, &events); err != nil {
			t.Errorf("unmarshal: %v", err)
			return
		}
		receivedCount.Store(int64(len(events)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.BatchSize = 3

	u := New(q, cfg, nil, nil)
	_ = u.drainOnce(ctx)

	if got := receivedCount.Load(); got != 3 {
		t.Fatalf("expected exactly 3 events in the bounded request, got %d", got)
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

// spec:agent-event-uploader/permanent-client-errors-are-not-infinitely-retained/server-consistently-returns-4xx-for-a-malformed-event
//
// Pins the #253 quarantine contract: when the server returns a non-401 4xx for the same batch on every drain tick, the
// uploader MUST stop retransmitting after a bounded number of attempts. Sequence:
//
//  1. Enqueue one event. Set ClientErrorQuarantineThreshold=3 so the test is fast.
//  2. Stand up a 400-everytime server.
//  3. Drive drainOnce in a loop. Each tick: dequeue (returns the row because uploaded=0), upload (fails with 400),
//     RecordClientError bumps the row's client_error_count from 0->1, 1->2, 2->3 across the three ticks.
//  4. On the 3rd tick, the post-bump value reaches the threshold; RecordClientError sets uploaded=1 in the same
//     transaction and returns the row id as newly-quarantined. The audit-class log line fires once.
//  5. A 4th drainOnce returns immediately because DequeueBatch filters on uploaded=0 - the row is no longer visible.
//
// The assertion that locks in "MUST NOT retransmit indefinitely" is: the server's request counter stops climbing
// after the 3rd tick. The audit log line is asserted via a buffered slog handler.
func TestUpload_4xxExhaustsQuarantineAndAudits(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()
	require.NoError(t, q.Enqueue(ctx, []byte(`{"event_id":"poison-1"}`)), "enqueue seed event")

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest) // permanent 4xx; non-401 so the quarantine path is exercised
	}))
	defer srv.Close()

	auditLog := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(auditLog, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	cfg.ClientErrorQuarantineThreshold = 3
	u := New(q, cfg, nil, logger)

	t.Run("three failing drains hit the server", func(t *testing.T) {
		for i := range 3 {
			require.Errorf(t, u.drainOnce(ctx), "drain %d: expected an error (server is 400)", i)
		}
		assert.Equal(t, int32(3), requests.Load(), "exactly 3 server requests across the 3 drain ticks")
	})

	t.Run("fourth drain is a no-op against the server", func(t *testing.T) {
		// Row is quarantined (uploaded=1), so dequeue is empty and the server is NOT contacted.
		require.NoError(t, u.drainOnce(ctx), "post-quarantine drain MUST succeed cleanly with an empty queue")
		assert.Equal(t, int32(3), requests.Load(), "post-quarantine drain MUST NOT contact the server")
	})

	t.Run("audit log fires exactly once on threshold crossing", func(t *testing.T) {
		assert.Contains(t, auditLog.String(), "uploader.events_quarantined",
			"audit log line MUST be tagged audit=uploader.events_quarantined")
		assert.Equal(t, 1, strings.Count(auditLog.String(), "uploader.events_quarantined"),
			"audit log line MUST fire exactly once (only the drain tick that crossed the threshold)")
	})
}

// spec:agent-event-uploader/drain-on-shutdown/graceful-shutdown
//
// Restored from PR #254 prep where the test was drafted, found a real impl bug (Run passed the
// already-cancelled ctx into drainOnce, making DequeueBatch fail immediately so no drain ran), and
// removed because the assertion would have caught the bug rather than the marker. The fix in
// uploader.go's Run now builds a fresh context.WithTimeout for the shutdown branch, so a graceful
// shutdown actually drains queued events before Run returns. Pinned by depth==0 after Run exits;
// the prior bug would have left depth==1.
func TestUpload_GracefulShutdownDrainsRemaining(t *testing.T) {
	q := openTestQueue(t)
	parentCtx := t.Context()
	if err := q.Enqueue(parentCtx, []byte(`{"event_id":"drain-on-shutdown"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ServerURL = srv.URL
	// 10s Interval so the periodic ticker doesn't fire during this sub-second test. The drain MUST
	// happen via the ctx.Done() branch, not via a periodic tick.
	cfg.Interval = 10 * time.Second

	u := New(q, cfg, nil, nil)

	runCtx, cancel := context.WithCancel(parentCtx)
	done := make(chan error, 1)
	go func() { done <- u.Run(runCtx) }()

	// Yield long enough that Run is parked on the ticker / ctx.Done select before cancellation.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of ctx cancellation")
	}

	depth, _ := q.Depth(parentCtx)
	if depth != 0 {
		t.Fatalf("graceful-shutdown drain must mark queued events uploaded before Run returns; depth=%d", depth)
	}
}
