package mysql_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
)

// spec:server-detection-rules-engine/alert-evidence-is-self-contained/triggering-event-payloads-are-captured-at-alert-creation
func TestStore_InsertAlert_CapturesEventEvidence(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "ev-1", HostID: "h1", TimestampNs: 100, EventType: "network_connect", Payload: json.RawMessage(`{"pid":42,"remote":"1.2.3.4"}`)},
		{EventID: "ev-2", HostID: "h1", TimestampNs: 200, EventType: "dns_query", Payload: json.RawMessage(`{"pid":42,"name":"evil.example"}`)},
	}
	require.NoError(t, s.InsertEventsAt(ctx, events, 1000))

	// A process-less alert (Subject set, ProcessID 0) avoids needing a processes row for the FK; the evidence copy is what we exercise.
	alertID, created, err := s.InsertAlert(ctx, api.Alert{
		HostID: "h1", RuleID: "test_rule", Severity: api.SeverityHigh, Title: "t", Description: "d", Subject: "test:evidence",
	}, []string{"ev-1", "ev-2"})
	require.NoError(t, err)
	require.True(t, created)

	evidence, err := s.GetAlertEventPayloads(ctx, alertID)
	require.NoError(t, err)
	require.Len(t, evidence, 2, "both triggering events' envelopes are captured at alert creation")
	assert.Equal(t, []string{"ev-1", "ev-2"}, []string{evidence[0].EventID, evidence[1].EventID}, "ordered by timestamp")
	assert.Equal(t, "network_connect", evidence[0].EventType)
	assert.JSONEq(t, `{"pid":42,"remote":"1.2.3.4"}`, string(evidence[0].Payload), "payload captured verbatim")
	assert.JSONEq(t, `{"pid":42,"name":"evil.example"}`, string(evidence[1].Payload))
}

// spec:server-detection-rules-engine/alert-evidence-is-self-contained/evidence-survives-event-archive-expiry
func TestStore_AlertEvidence_SurvivesEventDeletion(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	require.NoError(t, s.InsertEventsAt(ctx, []api.Event{
		{EventID: "gone-1", HostID: "h1", TimestampNs: 100, EventType: "network_connect", Payload: json.RawMessage(`{"pid":7}`)},
	}, 1000))
	alertID, _, err := s.InsertAlert(ctx, api.Alert{
		HostID: "h1", RuleID: "test_rule", Severity: api.SeverityHigh, Title: "t", Description: "d", Subject: "test:survives",
	}, []string{"gone-1"})
	require.NoError(t, err)

	// Simulate the events aging out (and the cutover dropping the events table + its FK): drop the link, then the source event.
	_, err = s.DB().ExecContext(ctx, "DELETE FROM alert_events WHERE alert_id = ?", alertID)
	require.NoError(t, err)
	_, err = s.DB().ExecContext(ctx, "DELETE FROM events WHERE event_id = ?", "gone-1")
	require.NoError(t, err)

	evidence, err := s.GetAlertEventPayloads(ctx, alertID)
	require.NoError(t, err)
	require.Len(t, evidence, 1, "captured evidence is self-contained and survives the source event's deletion")
	assert.JSONEq(t, `{"pid":7}`, string(evidence[0].Payload))
}
