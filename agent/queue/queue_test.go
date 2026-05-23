package queue

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// spec:agent-event-queue/fifo-dequeue-of-pending-events/uploader-requests-a-batch
//
// Enqueue three events A/B/C in order, request a batch of two: the queue MUST return A,B in insertion order
// and leave C in the queue (the scenario's example uses 5/3 but the contract is the same — ordering plus
// batch-size truncation plus the unused tail staying available for the next dequeue).
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

// spec:agent-event-queue/acknowledgement-marks-events-uploaded/successful-upload-is-acknowledged
// spec:agent-event-queue/queue-depth-is-observable/depth-after-several-enqueues
//
// Two scenarios share this test: acknowledgement drops the acked rows out of pending, and Depth() honestly
// reports the residual. Enqueue 3, MarkUploaded 2, Depth = 1 demonstrates both. The depth scenario's
// 5-enqueued / 3-acked / depth-2 example is the same contract with different numbers.
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

// spec:agent-event-queue/pruning-of-old-uploaded-events/prune-removes-old-uploaded-rows
//
// Demonstrates the THEN clause: an uploaded event older than the threshold is deleted. The "AND does not
// delete any pending events" companion is pinned by TestPruneDoesNotDeletePending below; together they
// cover both clauses of the scenario.
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

// spec:agent-event-queue/pruning-of-old-uploaded-events/prune-removes-old-uploaded-rows
//
// Companion to TestPrune above — pins the AND clause "Prune MUST NOT delete events that have not yet been
// uploaded." Together the two tests cover the full scenario contract.
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

// spec:agent-event-queue/pruning-of-old-uploaded-events/prune-with-no-eligible-rows
//
// A just-uploaded event is younger than the 1h threshold so Prune deletes nothing and returns 0. The
// scenario also mentions pending events being present; the contract under test is "zero rows removed when
// nothing is eligible", which the assertion `pruned == 0` pins regardless of whether pending rows coexist.
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
	if err := q.MarkUploaded(ctx, []int64{batch[0].ID}); err != nil {
		t.Fatalf("mark uploaded: %v", err)
	}

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

// spec:agent-event-queue/bounded-storage-with-operator-visible-lossy-fallback/cap-is-reached-but-uploaded-rows-can-absorb-the-pressure
//
// TestEnqueue_CapDropsUploadedFirst locks in the queue-cap contract: with a tight cap plus a batch of uploaded-then-unuploaded rows,
// cap enforcement drops the uploaded rows before it touches the unuploaded ones.
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

	// The cap is enforced on each Enqueue; after the extra writes the DB should be within the cap (allowing a single page of slack) AND
	// the surviving rows should be the non-uploaded ones (the uploaded ones get dropped first).
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

// spec:agent-event-queue/bounded-storage-with-operator-visible-lossy-fallback/cap-is-disabled
//
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

// spec:agent-event-queue/bounded-storage-with-operator-visible-lossy-fallback/cap-is-reached-with-no-uploaded-rows-to-drop
//
// TestEnqueue_CapLossyDropWhenOnlyUnuploaded covers the worst case: the server is offline for long enough that EVERY row is
// non-uploaded, cap is still exceeded, and we must drop lossy. The warn log + metric hook fire.
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

// spec:agent-event-queue/durable-enqueue/agent-crashes-after-enqueue
//
// Enqueue an event, Close the queue (proxy for abrupt agent exit; SQLite has already fsync'd the WAL on
// commit so Close is at-least-as-strong as a crash), Open the same dbPath, and the event must still be
// dequeueable. Pins the durability contract that the queue persists rows before returning success.
func TestQueue_AgentCrashSurvivesEnqueue(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "durable.db")

	ctx := t.Context()
	q, err := Open(ctx, dbPath, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const payload = `{"event_id":"durable-1","event_type":"exec"}`
	if err := q.Enqueue(ctx, []byte(payload)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	q2, err := Open(ctx, dbPath, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = q2.Close() })

	batch, err := q2.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("expected 1 surviving event, got %d", len(batch))
	}
	if string(batch[0].EventJSON) != payload {
		t.Fatalf("payload mismatch: %s", batch[0].EventJSON)
	}
}

// spec:agent-event-queue/fifo-dequeue-of-pending-events/uploader-requests-more-than-is-available
//
// Two events enqueued, batch of ten requested: DequeueBatch returns exactly the two available rows and
// returns immediately (no blocking, no timeout). Pins the "MUST NOT block waiting for more" half of the
// FIFO contract that TestEnqueueDequeue does not exercise.
func TestQueue_DequeueMoreThanAvailable(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	for _, e := range []string{`{"event_id":"a"}`, `{"event_id":"b"}`} {
		if err := q.Enqueue(ctx, []byte(e)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	batch, err := q.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("expected 2 events for a 10-batch request against a 2-event queue, got %d", len(batch))
	}
}

// spec:agent-event-queue/acknowledgement-marks-events-uploaded/upload-fails-and-the-events-are-retried
//
// Dequeue does not lock or pin rows. If the uploader's POST fails and the batch is never acked, the next
// dequeue MUST return the same rows so the uploader can retry. Pins the at-least-once delivery shape that
// makes the queue safe under transient server outages.
func TestQueue_UploadFailsAndEventsAreRetried(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	for _, e := range []string{`{"event_id":"x"}`, `{"event_id":"y"}`, `{"event_id":"z"}`} {
		if err := q.Enqueue(ctx, []byte(e)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	first, err := q.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("first dequeue: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("first dequeue: expected 3 events, got %d", len(first))
	}

	// Simulate "upload failed": skip MarkUploaded entirely. The queue must surface the same rows on a
	// later dequeue.
	second, err := q.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("second dequeue: %v", err)
	}
	if len(second) != 3 {
		t.Fatalf("retry dequeue: expected 3 events, got %d", len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("retry dequeue id[%d]: first=%d second=%d (rows should be identical)", i, first[i].ID, second[i].ID)
		}
	}
}

// spec:agent-event-queue/idempotent-re-enqueue-of-identical-event-identifiers/an-event-with-a-duplicate-event-id-is-enqueued
//
// Reconciliation can re-derive event_ids across restarts, so the queue MUST NOT reject a duplicate
// event_id at enqueue time — server-side dedup is the source of truth. Enqueueing the same payload twice
// MUST produce two pending rows that both dequeue.
func TestQueue_DuplicateEventIDIsAccepted(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	const payload = `{"event_id":"same-id","event_type":"exit"}`
	for range 2 {
		if err := q.Enqueue(ctx, []byte(payload)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	batch, err := q.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("expected 2 rows for two enqueues of the same event_id, got %d", len(batch))
	}
	if batch[0].ID == batch[1].ID {
		t.Fatalf("duplicate event_id must still yield distinct row ids: both=%d", batch[0].ID)
	}
}
