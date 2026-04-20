package queue

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestEnqueueDequeue(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	events := []string{
		`{"event_id":"a","event_type":"exec"}`,
		`{"event_id":"b","event_type":"fork"}`,
		`{"event_id":"c","event_type":"exit"}`,
	}

	for _, e := range events {
		if err := q.Enqueue(ctx, []byte(e)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	depth, err := q.Depth(ctx)
	if err != nil {
		t.Fatalf("depth: %v", err)
	}
	if depth != 3 {
		t.Fatalf("expected depth 3, got %d", depth)
	}

	batch, err := q.DequeueBatch(ctx, 2)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("expected 2 events, got %d", len(batch))
	}
	if string(batch[0].EventJSON) != events[0] {
		t.Errorf("event 0 mismatch: %s", batch[0].EventJSON)
	}
	if string(batch[1].EventJSON) != events[1] {
		t.Errorf("event 1 mismatch: %s", batch[1].EventJSON)
	}
}

func TestMarkUploaded(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	for range 3 {
		if err := q.Enqueue(ctx, []byte(`{"event_id":"x"}`)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	batch, err := q.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}

	ids := make([]int64, len(batch))
	for i, e := range batch {
		ids[i] = e.ID
	}

	if err := q.MarkUploaded(ctx, ids[:2]); err != nil {
		t.Fatalf("mark uploaded: %v", err)
	}

	depth, _ := q.Depth(ctx)
	if depth != 1 {
		t.Fatalf("expected depth 1 after marking 2 uploaded, got %d", depth)
	}
}

func TestPrune(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"old"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	batch, err := q.DequeueBatch(ctx, 1)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("expected 1 dequeued event, got %d", len(batch))
	}
	if err := q.MarkUploaded(ctx, []int64{batch[0].ID}); err != nil {
		t.Fatalf("mark uploaded: %v", err)
	}

	// Prune with zero duration should delete the uploaded event.
	pruned, err := q.Prune(ctx, 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}
}

func TestPruneDoesNotDeletePending(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"pending"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Prune should not touch non-uploaded events.
	pruned, err := q.Prune(ctx, 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("expected 0 pruned, got %d", pruned)
	}

	depth, _ := q.Depth(ctx)
	if depth != 1 {
		t.Fatalf("expected depth 1, got %d", depth)
	}
}

func TestPruneRespectsAge(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	if err := q.Enqueue(ctx, []byte(`{"event_id":"recent"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	batch, err := q.DequeueBatch(ctx, 1)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("expected 1 dequeued event, got %d", len(batch))
	}
	_ = q.MarkUploaded(ctx, []int64{batch[0].ID})

	// Prune with 1 hour should not delete a just-created event.
	pruned, err := q.Prune(ctx, time.Hour)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("expected 0 pruned for recent event, got %d", pruned)
	}
}

func openTestQueue(t *testing.T) *Queue {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	q, err := Open(t.Context(), dbPath, Options{})
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

// openCappedQueue is the cap-testing helper. maxBytes is the soft cap. Keep the tests
// sub-second by using small caps (64 KiB or so) and ~1 KiB events.
func openCappedQueue(t *testing.T, maxBytes int64) *Queue {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	q, err := Open(t.Context(), dbPath, Options{MaxBytes: maxBytes})
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

// TestEnqueue_CapDropsUploadedFirst locks in the Phase 4 queue-cap contract: with a
// tight cap plus a batch of uploaded-then-unuploaded rows, cap enforcement drops the
// uploaded rows before it touches the unuploaded ones.
func TestEnqueue_CapDropsUploadedFirst(t *testing.T) {
	// ~1 KiB payload so the SQLite main file grows in predictable ~4 KiB page steps.
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = 'x'
	}

	// Cap at 64 KiB; SQLite page size is typically 4 KiB so we get ~16 pages.
	q := openCappedQueue(t, 64*1024)
	ctx := t.Context()

	// Write 200 events; the first 100 get marked uploaded via DequeueBatch below.
	for i := range 200 {
		if err := q.Enqueue(ctx, payload); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	// Grab the first 100 event ids and mark them uploaded.
	batch, err := q.DequeueBatch(ctx, 100)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	ids := make([]int64, 0, len(batch))
	for _, e := range batch {
		ids = append(ids, e.ID)
	}
	if err := q.MarkUploaded(ctx, ids); err != nil {
		t.Fatalf("mark uploaded: %v", err)
	}

	// Write more events to push past the cap.
	for range 200 {
		if err := q.Enqueue(ctx, payload); err != nil {
			t.Fatalf("enqueue over cap: %v", err)
		}
	}

	// The cap is enforced on each Enqueue; after the extra writes the DB should be
	// within the cap (allowing a single page of slack) AND the surviving rows should
	// be the non-uploaded ones (the uploaded ones get dropped first).
	size, err := q.dbSizeBytes(ctx)
	if err != nil {
		t.Fatalf("dbSizeBytes: %v", err)
	}
	if size > 64*1024+8192 { // +8 KiB slack for SQLite page alignment
		t.Fatalf("DB size %d > cap + slack; cap enforcement failed", size)
	}

	depth, err := q.Depth(ctx)
	if err != nil {
		t.Fatalf("depth: %v", err)
	}
	if depth == 0 {
		t.Fatalf("all non-uploaded events were dropped — expected uploaded-first policy")
	}
}

// TestEnqueue_CapIsNoOpWhenUnbounded proves MaxBytes=0 preserves pre-Phase-4
// unbounded behaviour. The DB is allowed to grow past any cap.
func TestEnqueue_CapIsNoOpWhenUnbounded(t *testing.T) {
	q := openCappedQueue(t, 0) // explicit zero
	ctx := t.Context()
	payload := make([]byte, 1024)

	// Write enough to blow past any plausible cap.
	for range 100 {
		if err := q.Enqueue(ctx, payload); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	depth, err := q.Depth(ctx)
	if err != nil {
		t.Fatalf("depth: %v", err)
	}
	if depth != 100 {
		t.Fatalf("unbounded queue must not drop: depth=%d, want 100", depth)
	}
}

// TestEnqueue_CapLossyDropWhenOnlyUnuploaded covers the worst case: the server is
// offline for long enough that EVERY row is non-uploaded, cap is still exceeded,
// and we must drop lossy. The warn log + metric hook fire.
func TestEnqueue_CapLossyDropWhenOnlyUnuploaded(t *testing.T) {
	q := openCappedQueue(t, 32*1024) // very tight cap so a handful of ~1 KiB rows triggers drop
	ctx := t.Context()
	payload := make([]byte, 1024)

	var stub stubMetrics
	q.SetMetrics(&stub)

	for range 200 {
		if err := q.Enqueue(ctx, payload); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	// At some point the cap enforced a lossy drop. The stub should have recorded at
	// least one lossy call.
	if !stub.hadLossy() {
		t.Fatalf("expected at least one lossy drop; metrics stub saw none")
	}
}

type stubMetrics struct {
	dropped []stubDrop
}

type stubDrop struct {
	n     int64
	lossy bool
}

func (s *stubMetrics) QueueDropped(_ context.Context, n int64, lossy bool) {
	s.dropped = append(s.dropped, stubDrop{n: n, lossy: lossy})
}

func (s *stubMetrics) hadLossy() bool {
	for _, d := range s.dropped {
		if d.lossy {
			return true
		}
	}
	return false
}
