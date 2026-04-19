package store

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInsertAndGetAlert(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	// Insert a process to reference.
	procID, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/usr/bin/python3", ForkTimeNs: 1000})
	require.NoError(t, err)

	// Insert an event to link.
	err = s.InsertEvents(ctx, []Event{
		{EventID: "evt-1", HostID: "host-a", TimestampNs: 1000, EventType: "exec", Payload: json.RawMessage(`{"pid":100}`)},
	})
	require.NoError(t, err)

	alert := Alert{
		HostID:      "host-a",
		RuleID:      "suspicious_exec",
		Severity:    "high",
		Title:       "Suspicious exec from temp path",
		Description: "python3 → /bin/sh → /tmp/payload",
		ProcessID:   procID,
	}

	id, created, err := s.InsertAlert(ctx, alert, []string{"evt-1"})
	require.NoError(t, err)
	assert.True(t, created)
	assert.Positive(t, id)

	got, err := s.GetAlert(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "host-a", got.HostID)
	assert.Equal(t, "suspicious_exec", got.RuleID)
	assert.Equal(t, "high", got.Severity)
	assert.Equal(t, "open", got.Status)
	assert.Equal(t, procID, got.ProcessID)

	eventIDs, err := s.GetAlertEventIDs(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []string{"evt-1"}, eventIDs)
}

func TestInsertAlertDeduplication(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/usr/bin/python3", ForkTimeNs: 1000})
	require.NoError(t, err)

	alert := Alert{
		HostID:    "host-a",
		RuleID:    "suspicious_exec",
		Severity:  "high",
		Title:     "Alert 1",
		ProcessID: procID,
	}

	firstID, created, err := s.InsertAlert(ctx, alert, nil)
	require.NoError(t, err)
	assert.True(t, created)

	// Same (host_id, rule_id, process_id) should return existing ID.
	alert.Title = "Alert 2 (should be deduped)"
	secondID, created, err := s.InsertAlert(ctx, alert, nil)
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, firstID, secondID)
}

func TestListAlerts(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	procIDLow, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)
	procIDHigh, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 200, PPID: 1, Path: "/bin/sh", ForkTimeNs: 2000})
	require.NoError(t, err)

	_, _, err = s.InsertAlert(ctx, Alert{HostID: "host-a", RuleID: "r1", Severity: "low", Title: "Low alert", ProcessID: procIDLow}, nil)
	require.NoError(t, err)
	_, _, err = s.InsertAlert(ctx, Alert{HostID: "host-a", RuleID: "r2", Severity: "high", Title: "High alert", ProcessID: procIDHigh}, nil)
	require.NoError(t, err)

	t.Run("all alerts", func(t *testing.T) {
		alerts, err := s.ListAlerts(ctx, AlertFilter{})
		require.NoError(t, err)
		assert.Len(t, alerts, 2)
	})

	t.Run("filter by severity", func(t *testing.T) {
		alerts, err := s.ListAlerts(ctx, AlertFilter{Severity: "high"})
		require.NoError(t, err)
		assert.Len(t, alerts, 1)
		assert.Equal(t, "High alert", alerts[0].Title)
	})

	t.Run("filter by host", func(t *testing.T) {
		alerts, err := s.ListAlerts(ctx, AlertFilter{HostID: "host-b"})
		require.NoError(t, err)
		assert.Empty(t, alerts)
	})

	t.Run("filter by status", func(t *testing.T) {
		alerts, err := s.ListAlerts(ctx, AlertFilter{Status: "resolved"})
		require.NoError(t, err)
		assert.Empty(t, alerts)
	})
}

func TestUpdateAlertStatus(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)

	id, _, err := s.InsertAlert(ctx, Alert{
		HostID: "host-a", RuleID: "r1", Severity: "high", Title: "Test", ProcessID: procID,
	}, nil)
	require.NoError(t, err)

	t.Run("acknowledge", func(t *testing.T) {
		err := s.UpdateAlertStatus(ctx, id, "acknowledged", 0)
		require.NoError(t, err)

		got, err := s.GetAlert(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "acknowledged", got.Status)
		assert.Nil(t, got.ResolvedAt)
	})

	t.Run("resolve", func(t *testing.T) {
		err := s.UpdateAlertStatus(ctx, id, "resolved", 0)
		require.NoError(t, err)

		got, err := s.GetAlert(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "resolved", got.Status)
		assert.NotNil(t, got.ResolvedAt)
	})

	t.Run("reopen clears resolved_at", func(t *testing.T) {
		err := s.UpdateAlertStatus(ctx, id, "open", 0)
		require.NoError(t, err)

		got, err := s.GetAlert(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "open", got.Status)
		assert.Nil(t, got.ResolvedAt)
	})
}

func TestGetAlertNotFound(t *testing.T) {
	s := OpenTestStore(t)
	got, err := s.GetAlert(t.Context(), 99999)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestGetAlertsByProcessID(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)

	_, _, err = s.InsertAlert(ctx, Alert{HostID: "host-a", RuleID: "r1", Severity: "high", Title: "Alert", ProcessID: procID}, nil)
	require.NoError(t, err)

	alerts, err := s.GetAlertsByProcessID(ctx, procID)
	require.NoError(t, err)
	assert.Len(t, alerts, 1)

	empty, err := s.GetAlertsByProcessID(ctx, 99999)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestCountAlerts(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)
	procIDOther, err := s.InsertProcess(ctx, Process{HostID: "host-a", PID: 200, PPID: 1, Path: "/bin/sh", ForkTimeNs: 2000})
	require.NoError(t, err)

	_, _, err = s.InsertAlert(ctx, Alert{HostID: "host-a", RuleID: "r1", Severity: "high", Title: "A1", ProcessID: procID}, nil)
	require.NoError(t, err)
	_, _, err = s.InsertAlert(ctx, Alert{HostID: "host-a", RuleID: "r2", Severity: "low", Title: "A2", ProcessID: procIDOther}, nil)
	require.NoError(t, err)

	count, err := s.CountAlerts(ctx, AlertFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	count, err = s.CountAlerts(ctx, AlertFilter{Severity: "high"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}
