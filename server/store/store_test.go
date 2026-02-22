package store

import (
	"encoding/json"
	"os"
	"testing"
)

// These tests require a PostgreSQL instance.
// Set EDR_TEST_DSN to run them (e.g., "postgres://localhost/edr_test?sslmode=disable").

func TestInsertAndCount(t *testing.T) {
	s := openTestStore(t)

	events := []Event{
		{
			EventID:     "test-001",
			HostID:      "host-1",
			TimestampNs: 1700000000000000000,
			EventType:   "exec",
			Payload:     json.RawMessage(`{"pid":1234,"ppid":1,"path":"/usr/bin/ls"}`),
		},
		{
			EventID:     "test-002",
			HostID:      "host-1",
			TimestampNs: 1700000000000000001,
			EventType:   "fork",
			Payload:     json.RawMessage(`{"child_pid":1235,"parent_pid":1234}`),
		},
	}

	if err := s.InsertEvents(events); err != nil {
		t.Fatalf("insert: %v", err)
	}

	count, err := s.CountEvents()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected at least 2 events, got %d", count)
	}
}

func TestInsertDuplicateIsIdempotent(t *testing.T) {
	s := openTestStore(t)

	event := Event{
		EventID:     "dup-test-001",
		HostID:      "host-1",
		TimestampNs: 1700000000000000000,
		EventType:   "exec",
		Payload:     json.RawMessage(`{"pid":1}`),
	}

	if err := s.InsertEvents([]Event{event}); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Insert again — should not error.
	if err := s.InsertEvents([]Event{event}); err != nil {
		t.Fatalf("duplicate insert: %v", err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping PostgreSQL tests")
	}

	s, err := New(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
