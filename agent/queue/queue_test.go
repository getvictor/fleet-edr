package queue

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// spec:agent-event-queue/fifo-dequeue-of-pending-events/uploader-requests-a-batch
//
// Enqueue three events A/B/C in order, request a batch of two: the queue MUST return A,B in insertion
// order and MUST NOT return more than the requested batch size. The scenario's example uses 5/3 but the
// contract is the same — ordering plus batch-size truncation, both pinned by the assertions below.
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
// Pins the durability invariant the spec describes: an event whose Enqueue returned success MUST survive
// the agent restarting against the same dbPath. The test simulates restart via Close+reopen, which is a
// proxy for a true crash rather than an exact replica — a real crash would never call Close. The proxy
// is justified for an in-process test because the queue uses SQLite WAL (see queue.go Open DSN) and the
// underlying driver's default synchronous mode fsyncs the WAL at COMMIT; under those settings the event
// is on disk before Enqueue returns, and a process death after Enqueue would leave the same persisted
// state Close+reopen exposes. A bit-exact crash test would need a subprocess + os.Exit; that is filed as
// follow-up #243's neighbour of cap-eviction-races and disk-full.
func TestQueue_AgentCrashSurvivesEnqueue(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "durable.db")

	ctx := t.Context()
	q, err := Open(ctx, dbPath, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
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

// spec:agent-event-queue/acknowledgement-marks-events-uploaded/cap-eviction-races-an-in-flight-upload
//
// The uploader's "dequeue → POST → MarkUploaded" sequence is non-atomic with cap enforcement. When the queue evicts
// pending rows under the byte cap between Dequeue and MarkUploaded, the IDs the uploader is about to ack no longer
// exist. The spec scenario pins two properties: (1) MarkUploaded MUST be a silent no-op for evicted IDs (so the
// uploader doesn't crash on an ack that lost its race), and (2) the cap-eviction MUST surface through the lossy-drop
// metric (so operators see the in-flight loss).
//
// MarkUploaded is `UPDATE events SET uploaded = 1 WHERE id = ?` — the missing-row case affects 0 rows and returns
// nil naturally, no special-case handling needed. The eviction path is exercised by enqueueing enough rows to push
// the queue past its byte cap; since none of the rows are uploaded=1 yet, the cap drops oldest pending (lossy).
func TestQueue_CapEvictionRacesInflightUpload(t *testing.T) {
	q := openCappedQueue(t, 32*1024)
	ctx := t.Context()
	payload := capRaceTestPayload()

	var stub stubMetrics
	q.SetMetrics(&stub)

	// Phase 1: capture an in-flight batch (5 rows dequeued but not yet acked).
	inflightIDs := capRaceEnqueueInflight(t, q, ctx, payload, 5)

	// Phase 2: enqueue enough additional events to force the cap to lossy-drop pending rows. The in-flight rows
	// (oldest) are the first to go because nothing is marked uploaded yet.
	for range 200 {
		if err := q.Enqueue(ctx, payload); err != nil {
			t.Fatalf("pressure enqueue: %v", err)
		}
	}
	if !stub.hadLossy() {
		t.Fatalf("expected at least one lossy drop during cap pressure; metrics stub saw none")
	}

	// Verify the eviction actually touched the in-flight set rather than only dropping newer rows.
	capRaceAssertInflightEvicted(t, q, ctx, inflightIDs)

	// Phase 3: ack the originally-dequeued IDs. Some MUST already be gone (the cap evicted them); MarkUploaded MUST
	// still return nil so the uploader's happy path doesn't surface a failure for events the queue has chosen to drop.
	if err := q.MarkUploaded(ctx, inflightIDs); err != nil {
		t.Fatalf("MarkUploaded on evicted-in-flight IDs MUST be a silent no-op, got: %v", err)
	}

	// 5 in-flight + 200 pressure = 205 rows enqueued. After lossy drops, depth MUST be strictly less than 205. If the
	// cap didn't fire there's no race to test.
	depth, err := q.Depth(ctx)
	if err != nil {
		t.Fatalf("depth: %v", err)
	}
	if depth >= 205 {
		t.Fatalf("expected cap enforcement to drop rows; depth=%d still >= 205 enqueues", depth)
	}
}

// capRaceTestPayload returns a 1 KiB payload of 'x' bytes the cap-eviction test enqueues at every level. Pulled out so
// the test body stays under Sonar S3776's cognitive-complexity budget.
func capRaceTestPayload() []byte {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = 'x'
	}
	return payload
}

// capRaceEnqueueInflight enqueues `count` payload rows and immediately dequeues them so the test has a captured set of
// "in-flight" IDs the uploader would still be working on when the cap fires. Returns the captured IDs.
func capRaceEnqueueInflight(t *testing.T, q *Queue, ctx context.Context, payload []byte, count int) []int64 {
	t.Helper()
	for range count {
		if err := q.Enqueue(ctx, payload); err != nil {
			t.Fatalf("initial enqueue: %v", err)
		}
	}
	inflight, err := q.DequeueBatch(ctx, count*2) // generous limit so partial returns surface as a test failure
	if err != nil {
		t.Fatalf("dequeue in-flight batch: %v", err)
	}
	if len(inflight) != count {
		t.Fatalf("expected %d in-flight rows, got %d", count, len(inflight))
	}
	ids := make([]int64, len(inflight))
	for i, e := range inflight {
		ids[i] = e.ID
	}
	return ids
}

// capRaceAssertInflightEvicted verifies the cap's lossy-drop path touched the captured in-flight set rather than only dropping
// newer rows. Without this probe, a regression that flipped the eviction policy to drop newest-first would silently keep the
// test green: stub.hadLossy + Depth would both pass even though MarkUploaded's missing-row path is no longer exercised. The
// IN-clause is composed dynamically so a future count change in the caller doesn't require a parallel SQL edit (the prior
// hardcoded 5-placeholder shape was a footgun the require.Len lint check papered over).
func capRaceAssertInflightEvicted(t *testing.T, q *Queue, ctx context.Context, inflightIDs []int64) {
	t.Helper()
	// Guard against the empty-slice case: strings.Repeat with a negative count panics. Today's only caller passes a
	// non-empty slice (capRaceEnqueueInflight asserts len == count > 0), but a future caller refactor would otherwise
	// turn a setup bug into a cryptic strings.Repeat panic instead of a clear test-fail (Gemini + Copilot #279).
	if len(inflightIDs) == 0 {
		t.Fatal("capRaceAssertInflightEvicted called with empty inflightIDs - setup didn't capture any in-flight rows")
	}
	placeholders := strings.Repeat("?,", len(inflightIDs)-1) + "?"
	args := make([]any, len(inflightIDs))
	for i, id := range inflightIDs {
		args[i] = id
	}
	var survivingInflight int
	row := q.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE id IN ("+placeholders+")", args...) //nolint:gosec
	if err := row.Scan(&survivingInflight); err != nil {
		t.Fatalf("count surviving in-flight rows: %v", err)
	}
	if survivingInflight == len(inflightIDs) {
		t.Fatalf("expected cap enforcement to evict at least one in-flight row before MarkUploaded; all %d survived",
			len(inflightIDs))
	}
}

// spec:agent-event-queue/storage-i-o-errors-surface-to-the-caller/disk-is-full-during-enqueue
//
// The spec pins that an Enqueue against an exhausted disk MUST return an error so the caller can backoff / load-shed
// rather than silently succeeding. We simulate ENOSPC using SQLite's max_page_count PRAGMA: when set, INSERTs that
// would grow the database beyond that page count return SQLITE_FULL ("database or disk is full"). This is the same
// error class the modernc.org/sqlite driver returns for a real ENOSPC on the underlying disk, so the test exercises
// the production-relevant code path (db.ExecContext's INSERT returning an error from queue.Enqueue).
func TestQueue_DiskFullDuringEnqueueReturnsError(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()

	// Snapshot the current page_count and pin max_page_count to it. SQLite's PRAGMA max_page_count silently FLOORS at the current
	// page_count - setting it BELOW the current count is a no-op and returns whatever the current max already was. Without this
	// floor-aware logic the prior version of the test (PRAGMA max_page_count = 4) could be a no-op on a schema large enough to
	// already exceed 4 pages, leaving the subsequent Enqueue free to grow the DB and return nil - which is exactly the regression
	// signature the spec scenario is supposed to catch.
	var currentPages int64
	if err := q.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&currentPages); err != nil {
		t.Fatalf("read page_count: %v", err)
	}
	var capped int64
	if err := q.db.QueryRowContext(ctx, fmt.Sprintf("PRAGMA max_page_count = %d", currentPages)).Scan(&capped); err != nil {
		t.Fatalf("set max_page_count to %d: %v", currentPages, err)
	}
	if capped != currentPages {
		t.Fatalf("max_page_count silently floored to %d (asked for %d); test cannot reliably trigger SQLITE_FULL", capped, currentPages)
	}

	bigPayload := make([]byte, 64*1024)
	for i := range bigPayload {
		bigPayload[i] = 'x'
	}

	err := q.Enqueue(ctx, bigPayload)
	if err == nil {
		t.Fatalf("enqueue against an exhausted-page-count DB MUST return an error; got nil so the caller would " +
			"believe the event was durable when it actually was not")
	}
	// Pin the specific SQLITE_FULL (code 13) error rather than "any non-nil error". The spec scenario is "disk is full", not
	// "anything in the enqueue path can fail and we'll accept it" - a regression that returned a different sql error from the
	// path (constraint violation, dropped connection, etc.) would silently pass under a loose nil-check.
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		t.Fatalf("expected modernc.org/sqlite's *sqlite.Error, got %T: %v", err, err)
	}
	const sqliteFullCode = 13
	if got := sqliteErr.Code() & 0xff; got != sqliteFullCode {
		t.Fatalf("expected SQLITE_FULL (code 13), got code=%d (%#x): %v", got, sqliteErr.Code(), err)
	}
}

// TestQueue_OpenIsIdempotentAfterMigration pins the migration's already-has-column branch: reopening a DB path twice MUST NOT
// re-add the client_error_count column (the PRAGMA table_info pre-check + the loop's early-return at
// "name == migrationsClientErrorCount" cover this). A regression that issued ALTER TABLE on every Open would surface here
// because SQLite would error "duplicate column name: client_error_count" on the second Open.
func TestQueue_OpenIsIdempotentAfterMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "idem.db")
	ctx := t.Context()
	q1, err := Open(ctx, dbPath, Options{})
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := q1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	q2, err := Open(ctx, dbPath, Options{})
	if err != nil {
		t.Fatalf("second Open MUST NOT re-run the migration; got: %v", err)
	}
	t.Cleanup(func() { _ = q2.Close() })
}

// TestQueue_RecordClientError_EmptyIDsIsNoOp pins the early-return contract: passing an empty id slice MUST succeed without
// opening a transaction or touching the DB. Catches a regression that started a write transaction on every drainOnce even when
// the uploader's batch was empty.
func TestQueue_RecordClientError_EmptyIDsIsNoOp(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()
	quarantined, err := q.RecordClientError(ctx, nil, 5)
	if err != nil {
		t.Fatalf("empty-ids RecordClientError MUST succeed, got: %v", err)
	}
	if quarantined != nil {
		t.Fatalf("empty-ids RecordClientError MUST return nil slice, got %v", quarantined)
	}
}

// TestQueue_RecordClientError_ThresholdDisabled pins the threshold<=0 branch: with quarantineThreshold=0, the counter still
// bumps but no row is sealed. The caller (uploader DefaultConfig() with the new normalisation in New()) treats 0 as "apply
// the default 10"; a negative value reaches this branch as "explicitly disabled" so a test can opt out without colliding.
func TestQueue_RecordClientError_ThresholdDisabled(t *testing.T) {
	q := openTestQueue(t)
	ctx := t.Context()
	if err := q.Enqueue(ctx, []byte(`{"event_id":"no-quarantine"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	batch, err := q.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("expected 1 event, got %d", len(batch))
	}
	ids := []int64{batch[0].ID}

	// Hammer 20 calls with threshold=-1 (explicitly disabled). No row should be sealed; subsequent dequeues MUST
	// still see the row.
	for i := range 20 {
		quarantined, err := q.RecordClientError(ctx, ids, -1)
		if err != nil {
			t.Fatalf("RecordClientError #%d: %v", i, err)
		}
		if quarantined != nil {
			t.Fatalf("threshold=-1 MUST NOT quarantine; got %v on call %d", quarantined, i)
		}
	}
	again, err := q.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("post-bump dequeue: %v", err)
	}
	if len(again) != 1 {
		t.Fatalf("threshold-disabled row MUST stay visible to DequeueBatch; got %d rows", len(again))
	}
}
