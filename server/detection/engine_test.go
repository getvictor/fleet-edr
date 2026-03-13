package detection

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

// stubRule is a test rule that returns preconfigured findings.
type stubRule struct {
	id       string
	findings []Finding
	err      error
}

func (r *stubRule) ID() string { return r.id }
func (r *stubRule) Evaluate(_ context.Context, _ []store.Event, _ *store.Store) ([]Finding, error) {
	return r.findings, r.err
}

func TestEngineEvaluatePersistsAlerts(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	// Create a process to reference.
	procID, err := s.InsertProcess(ctx, store.Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)

	// Create an event to link.
	err = s.InsertEvents(ctx, []store.Event{
		{EventID: "evt-det-1", HostID: "host-a", TimestampNs: 1000, EventType: "exec", Payload: json.RawMessage(`{"pid":100}`)},
	})
	require.NoError(t, err)

	engine := NewEngine(s, slog.Default())
	engine.Register(&stubRule{
		id: "test_rule",
		findings: []Finding{
			{
				HostID:      "host-a",
				RuleID:      "test_rule",
				Severity:    SeverityHigh,
				Title:       "Test alert",
				Description: "A test detection",
				ProcessID:   procID,
				EventIDs:    []string{"evt-det-1"},
			},
		},
	})

	// Run evaluation — should persist the alert.
	engine.Evaluate(ctx, []store.Event{
		{EventID: "evt-det-1", HostID: "host-a", TimestampNs: 1000, EventType: "exec", Payload: json.RawMessage(`{"pid":100}`)},
	})

	// Verify alert was created.
	alerts, err := s.ListAlerts(ctx, store.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Equal(t, "test_rule", alerts[0].RuleID)
	assert.Equal(t, "high", alerts[0].Severity)
	assert.Equal(t, "Test alert", alerts[0].Title)

	// Verify event was linked.
	eventIDs, err := s.GetAlertEventIDs(ctx, alerts[0].ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"evt-det-1"}, eventIDs)
}

func TestEngineEvaluateDeduplicates(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, store.Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)

	engine := NewEngine(s, slog.Default())
	engine.Register(&stubRule{
		id: "test_rule",
		findings: []Finding{
			{HostID: "host-a", RuleID: "test_rule", Severity: SeverityHigh, Title: "Dup", ProcessID: procID},
		},
	})

	events := []store.Event{{EventID: "e1", HostID: "host-a", TimestampNs: 1000, EventType: "exec"}}

	// Run twice — second run should not create a duplicate.
	engine.Evaluate(ctx, events)
	engine.Evaluate(ctx, events)

	count, err := s.CountAlerts(ctx, store.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestEngineEvaluateRuleError(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	engine := NewEngine(s, slog.Default())
	engine.Register(&stubRule{
		id:  "failing_rule",
		err: assert.AnError,
	})

	// Should not panic — errors are logged, not returned.
	engine.Evaluate(ctx, []store.Event{{EventID: "e1", HostID: "host-a"}})

	count, err := s.CountAlerts(ctx, store.AlertFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}
