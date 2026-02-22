package queue

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEnqueueDequeue(t *testing.T) {
	q := openTestQueue(t)

	events := []string{
		`{"event_id":"a","event_type":"exec"}`,
		`{"event_id":"b","event_type":"fork"}`,
		`{"event_id":"c","event_type":"exit"}`,
	}

	for _, e := range events {
		if err := q.Enqueue([]byte(e)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	depth, err := q.Depth()
	if err != nil {
		t.Fatalf("depth: %v", err)
	}
	if depth != 3 {
		t.Fatalf("expected depth 3, got %d", depth)
	}

	batch, err := q.DequeueBatch(2)
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

	for i := range 3 {
		_ = i
		if err := q.Enqueue([]byte(`{"event_id":"x"}`)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	batch, err := q.DequeueBatch(10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}

	ids := make([]int64, len(batch))
	for i, e := range batch {
		ids[i] = e.ID
	}

	if err := q.MarkUploaded(ids[:2]); err != nil {
		t.Fatalf("mark uploaded: %v", err)
	}

	depth, _ := q.Depth()
	if depth != 1 {
		t.Fatalf("expected depth 1 after marking 2 uploaded, got %d", depth)
	}
}

func TestPrune(t *testing.T) {
	q := openTestQueue(t)

	if err := q.Enqueue([]byte(`{"event_id":"old"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	batch, _ := q.DequeueBatch(1)
	if err := q.MarkUploaded([]int64{batch[0].ID}); err != nil {
		t.Fatalf("mark uploaded: %v", err)
	}

	// Prune with zero duration should delete the uploaded event.
	pruned, err := q.Prune(0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}
}

func TestPruneDoesNotDeletePending(t *testing.T) {
	q := openTestQueue(t)

	if err := q.Enqueue([]byte(`{"event_id":"pending"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Prune should not touch non-uploaded events.
	pruned, err := q.Prune(0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("expected 0 pruned, got %d", pruned)
	}

	depth, _ := q.Depth()
	if depth != 1 {
		t.Fatalf("expected depth 1, got %d", depth)
	}
}

func TestPruneRespectsAge(t *testing.T) {
	q := openTestQueue(t)

	if err := q.Enqueue([]byte(`{"event_id":"recent"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	batch, _ := q.DequeueBatch(1)
	_ = q.MarkUploaded([]int64{batch[0].ID})

	// Prune with 1 hour should not delete a just-created event.
	pruned, err := q.Prune(time.Hour)
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
	q, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}
