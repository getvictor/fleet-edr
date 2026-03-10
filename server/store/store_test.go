package store

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests require a MySQL 8.4 instance.
// Set EDR_TEST_DSN to run them (e.g., "root@tcp(127.0.0.1:3306)/edr_test").

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

	err := s.InsertEvents(events)
	require.NoError(t, err)

	count, err := s.CountEvents()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, int64(2))
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

	err := s.InsertEvents([]Event{event})
	require.NoError(t, err)

	// Insert again — should not error.
	err = s.InsertEvents([]Event{event})
	require.NoError(t, err)
}

func openTestStore(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}

	s, err := New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}
