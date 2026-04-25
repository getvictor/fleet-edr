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

func (r *stubRule) ID() string           { return r.id }
func (r *stubRule) Techniques() []string { return nil }
func (r *stubRule) Evaluate(_ context.Context, _ []store.Event, _ *store.Store) ([]Finding, error) {
	return r.findings, r.err
}

// recordingRule captures the events Engine.Evaluate handed it so tests
// can assert the engine did the right pre-filtering. Returns no findings.
type recordingRule struct {
	id   string
	seen []store.Event
}

func (r *recordingRule) ID() string           { return r.id }
func (r *recordingRule) Techniques() []string { return nil }
func (r *recordingRule) Evaluate(_ context.Context, events []store.Event, _ *store.Store) ([]Finding, error) {
	r.seen = append(r.seen, events...)
	return nil, nil
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
	err = engine.Evaluate(ctx, []store.Event{
		{EventID: "evt-det-1", HostID: "host-a", TimestampNs: 1000, EventType: "exec", Payload: json.RawMessage(`{"pid":100}`)},
	})
	require.NoError(t, err)

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
	require.NoError(t, engine.Evaluate(ctx, events))
	require.NoError(t, engine.Evaluate(ctx, events))

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

	// Rule evaluation errors are logged and skipped, not returned.
	require.NoError(t, engine.Evaluate(ctx, []store.Event{{EventID: "e1", HostID: "host-a"}}))

	count, err := s.CountAlerts(ctx, store.AlertFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// TestFilterSnapshotEvents pins the contract of the snapshot filter:
// snapshot=true exec events drop, everything else passes through. This
// keeps the per-event peek behaviour deterministic so future filters
// can stack without reordering surprises.
func TestFilterSnapshotEvents(t *testing.T) {
	cases := []struct {
		name   string
		input  store.Event
		filter bool
	}{
		{"exec snapshot=true",
			store.Event{EventType: "exec", Payload: jsonObj(`{"pid":1,"snapshot":true}`)}, true},
		{"exec snapshot=true with whitespace",
			store.Event{EventType: "exec", Payload: jsonObj(`{"pid":1, "snapshot": true }`)}, false},
		{"exec snapshot=false",
			store.Event{EventType: "exec", Payload: jsonObj(`{"pid":1,"snapshot":false}`)}, false},
		{"exec without snapshot field",
			store.Event{EventType: "exec", Payload: jsonObj(`{"pid":1}`)}, false},
		{"open with snapshot:true substring (other event type)",
			store.Event{EventType: "open", Payload: jsonObj(`{"pid":1,"snapshot":true}`)}, false},
		{"exec mentions snapshot in args (false-positive guard)",
			store.Event{EventType: "exec", Payload: jsonObj(`{"pid":1,"args":["echo","\"snapshot\":true"]}`)}, false},
		{"exec malformed JSON containing marker",
			store.Event{EventType: "exec", Payload: jsonObj(`{"snapshot":true,`)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filterSnapshotEvents([]store.Event{tc.input})
			if tc.filter {
				assert.Empty(t, out, "expected event to be dropped")
			} else {
				assert.Len(t, out, 1, "expected event to pass through")
			}
		})
	}

	// Whitespace-tolerant case: the bytes.Contains gate is intentionally
	// strict on the canonical Go-encoded shape. ESF events come from a
	// well-typed Swift encoder that emits no extra whitespace, so
	// "snapshot": true (with a space) wouldn't appear in production
	// payloads. The probe-decode follow-up doesn't run when the gate
	// rejects, so the spaced form falls through as "not snapshot". This
	// is documented behaviour, not a bug — flag it if Swift's encoder
	// ever changes its formatting.
	t.Run("whitespaced form passes through (gate is byte-exact)", func(t *testing.T) {
		out := filterSnapshotEvents([]store.Event{
			{EventType: "exec", Payload: jsonObj(`{"snapshot": true}`)},
		})
		assert.Len(t, out, 1)
	})
}

// TestEngineEvaluateDropsSnapshotExecs proves Engine.Evaluate hands
// rules only non-snapshot events. Wired through the full Evaluate call,
// not a direct filterSnapshotEvents test, so the integration with the
// rule iteration is locked down too.
func TestEngineEvaluateDropsSnapshotExecs(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	rec := &recordingRule{id: "recorder"}
	engine := NewEngine(s, slog.Default())
	engine.Register(rec)

	events := []store.Event{
		{EventID: "live-exec", HostID: "host-a", TimestampNs: 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"path":"/bin/ls"}`)},
		{EventID: "snap-exec", HostID: "host-a", TimestampNs: 2, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"path":"/Applications/Safari.app/Contents/MacOS/Safari","snapshot":true}`)},
		{EventID: "live-fork", HostID: "host-a", TimestampNs: 3, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":300,"parent_pid":1}`)},
	}
	require.NoError(t, engine.Evaluate(ctx, events))

	require.Len(t, rec.seen, 2, "rule must see live-exec + live-fork only")
	for _, e := range rec.seen {
		assert.NotEqual(t, "snap-exec", e.EventID,
			"snapshot exec must never reach the rule")
	}
}

// jsonObj is a tiny helper to keep the table above readable.
func jsonObj(s string) json.RawMessage { return json.RawMessage(s) }
