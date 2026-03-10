package store

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests require a MySQL 8.4 instance.
// Set EDR_TEST_DSN to run them (e.g., "root@tcp(127.0.0.1:3306)/edr_test?parseTime=true").

func TestInsertAndCount(t *testing.T) {
	s := OpenTestStore(t)

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

	err := s.InsertEvents(t.Context(), events)
	require.NoError(t, err)

	count, err := s.CountEvents(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestInsertDuplicateIsIdempotent(t *testing.T) {
	s := OpenTestStore(t)

	event := Event{
		EventID:     "dup-test-001",
		HostID:      "host-1",
		TimestampNs: 1700000000000000000,
		EventType:   "exec",
		Payload:     json.RawMessage(`{"pid":1}`),
	}

	err := s.InsertEvents(t.Context(), []Event{event})
	require.NoError(t, err)

	// Insert again — should not error.
	err = s.InsertEvents(t.Context(), []Event{event})
	require.NoError(t, err)
}

func TestFetchUnprocessedAndMarkProcessed(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	events := []Event{
		{EventID: "unproc-1", HostID: "host-1", TimestampNs: 1000, EventType: "exec", Payload: json.RawMessage(`{"pid":1}`)},
		{EventID: "unproc-2", HostID: "host-1", TimestampNs: 2000, EventType: "exec", Payload: json.RawMessage(`{"pid":2}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))

	unprocessed, err := s.FetchUnprocessed(ctx, 100)
	require.NoError(t, err)
	assert.Len(t, unprocessed, 2)

	require.NoError(t, s.MarkProcessed(ctx, []string{"unproc-1", "unproc-2"}))

	unprocessed, err = s.FetchUnprocessed(ctx, 100)
	require.NoError(t, err)
	assert.Empty(t, unprocessed)
}
