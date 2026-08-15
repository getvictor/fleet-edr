package catalog

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// recoveryFailedEvent builds the event the agent emits when its repair budget for a provider is spent.
func recoveryFailedEvent(id, host, provider, outcome string, attempts int) api.Event {
	payload, err := json.Marshal(map[string]any{"provider": provider, "outcome": outcome, "attempts": attempts})
	if err != nil {
		panic(err)
	}
	return api.Event{
		EventID:   id,
		HostID:    host,
		EventType: "sensor_recovery_failed",
		Payload:   payload,
	}
}

// evalRecoveryFailed runs the rule over one event. The archive is nil because this rule reads no history: unlike
// sensor_tamper, its input event is already terminal, and requiring a GraphReader here would imply otherwise.
func evalRecoveryFailed(t *testing.T, evt api.Event) []api.Finding {
	t.Helper()
	findings, err := (&SensorRecoveryFailed{}).Evaluate(context.Background(), []api.Event{evt}, nil)
	require.NoError(t, err)
	return findings
}

// spec:server-detection-rules-engine/edr-sensor-recovery-failure-detection/automatic-recovery-gives-up-and-raises-a-finding
func TestSensorRecoveryFailed_RaisesACriticalFinding(t *testing.T) {
	t.Parallel()
	findings := evalRecoveryFailed(t, recoveryFailedEvent("e1", "host-a", "content_filter", "enable_failed", 3))

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "sensor_recovery_failed", f.RuleID)
	assert.Equal(t, "host-a", f.HostID)
	assert.Equal(t, api.SeverityCritical, f.Severity,
		"critical, one above the stop it follows: the stop may have healed by the time anyone looks, this cannot have")
	assert.Equal(t, []string{"e1"}, f.EventIDs, "the finding must cite the record it fired on")
	assert.Contains(t, f.Description, "content_filter", "the finding must name the provider to restore")
	assert.Contains(t, f.Description, "3", "and how many repairs were attempted, so it reads as tried rather than skipped")
}

// spec:server-detection-rules-engine/edr-sensor-recovery-failure-detection/an-unrecognised-outcome-is-still-reported
//
// TestSensorRecoveryFailed_DescribesWhichFailureShape pins the half of the message that changes what a responder does
// next. Collapsing both shapes into "recovery failed" would leave them guessing between a broken host app and a fault
// that re-enabling cannot fix.
func TestSensorRecoveryFailed_DescribesWhichFailureShape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		outcome     string
		wantPhrase  string
		avoidPhrase string
	}{
		{
			name:        "the repair command kept failing",
			outcome:     "enable_failed",
			wantPhrase:  "every attempt to re-enable it failed",
			avoidPhrase: "reported success",
		},
		{
			name:        "the repair kept succeeding without effect",
			outcome:     "enable_ineffective",
			wantPhrase:  "reported success and it stayed stopped",
			avoidPhrase: "every attempt to re-enable it failed",
		},
		{
			name: "an outcome this build does not know",
			// Forward compatibility: a newer agent may report a shape this server has no phrasing for, and the finding
			// must still be raised and still be readable rather than being dropped or rendering an empty clause.
			outcome:     "some_future_outcome",
			wantPhrase:  "automatic recovery gave up",
			avoidPhrase: "some_future_outcome",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := evalRecoveryFailed(t, recoveryFailedEvent("e1", "host-a", "dns_proxy", tc.outcome, 3))
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0].Description, tc.wantPhrase)
			assert.NotContains(t, findings[0].Description, tc.avoidPhrase)
		})
	}
}

// TestSensorRecoveryFailed_SubjectCollapsesOneEventAndSeparatesDistinctOnes pins the dedup identity. The subject carries
// the event id rather than just the provider, so re-processing one exhaustion yields one alert while a genuinely new
// failure later is not silently suppressed by an old one.
func TestSensorRecoveryFailed_SubjectCollapsesOneEventAndSeparatesDistinctOnes(t *testing.T) {
	t.Parallel()
	first := evalRecoveryFailed(t, recoveryFailedEvent("e1", "host-a", "content_filter", "enable_failed", 3))
	again := evalRecoveryFailed(t, recoveryFailedEvent("e1", "host-a", "content_filter", "enable_failed", 3))
	later := evalRecoveryFailed(t, recoveryFailedEvent("e2", "host-a", "content_filter", "enable_failed", 3))

	require.Len(t, first, 1)
	require.Len(t, again, 1)
	require.Len(t, later, 1)
	assert.Equal(t, first[0].Subject, again[0].Subject, "re-processing one exhaustion must collapse to a single alert")
	assert.NotEqual(t, first[0].Subject, later[0].Subject, "a separate exhaustion must raise its own alert")
	assert.Contains(t, first[0].Subject, "content_filter")
}

// spec:server-detection-rules-engine/edr-sensor-recovery-failure-detection/a-repair-that-succeeds-raises-nothing
//
// TestSensorRecoveryFailed_IgnoresWhatIsNotItsEvent covers the inputs the rule sees on every batch and must stay silent
// on. The malformed cases matter because this rule runs against agent-supplied JSON: a payload it cannot read must be
// skipped, never turned into a finding that names no provider.
func TestSensorRecoveryFailed_IgnoresWhatIsNotItsEvent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		event api.Event
	}{
		{
			name:  "another event type",
			event: api.Event{EventID: "e1", HostID: "host-a", EventType: "exec", Payload: json.RawMessage(`{"pid":1}`)},
		},
		{
			name: "the provider transition it must not double-report",
			event: api.Event{EventID: "e1", HostID: "host-a", EventType: "sensor_provider_transition",
				Payload: json.RawMessage(`{"provider":"content_filter","state":"stopped"}`)},
		},
		{
			name: "unparseable payload",
			event: api.Event{EventID: "e1", HostID: "host-a", EventType: "sensor_recovery_failed",
				Payload: json.RawMessage(`{"provider":`)},
		},
		{
			name:  "no provider named",
			event: recoveryFailedEvent("e1", "host-a", "", "enable_failed", 3),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, evalRecoveryFailed(t, tc.event))
		})
	}
}

// spec:server-detection-rules-engine/edr-sensor-recovery-failure-detection/the-finding-outranks-the-stop-it-follows
//
// TestSensorRecoveryFailed_DocIsConsistentWithWhatItRaises guards the operator-facing surface against drifting from the
// behaviour. /api/rules and docs/detection-rules.md are generated from Doc, so a severity or technique that disagrees
// with the finding is a documented lie rather than a cosmetic slip.
func TestSensorRecoveryFailed_DocIsConsistentWithWhatItRaises(t *testing.T) {
	t.Parallel()
	r := &SensorRecoveryFailed{}
	doc := r.Doc()

	findings := evalRecoveryFailed(t, recoveryFailedEvent("e1", "host-a", "content_filter", "enable_failed", 3))
	require.Len(t, findings, 1)

	assert.Equal(t, doc.Severity, findings[0].Severity, "the documented severity must be the one actually raised")
	assert.Equal(t, doc.Title, findings[0].Title)
	assert.Equal(t, []string{"T1562.001"}, r.Techniques())
	assert.Equal(t, []string{"sensor_recovery_failed"}, doc.EventTypes,
		"the documented input event must be the one the rule reads, or an operator cannot tell what feeds it")
	assert.NotEqual(t, (&SensorTamper{}).ID(), r.ID())

	// And it must outrank the stop it follows. Asserting the RELATION rather than the literal severity is the point: if
	// someone later raises sensor_tamper to critical, this rule has to move too, or the alert list stops distinguishing
	// "may already be fixed" from "definitely still broken", which is the entire reason this rule exists.
	assert.Equal(t, api.SeverityHigh, (&SensorTamper{}).Doc().Severity, "guarding the comparison below against silent drift")
	assert.Equal(t, api.SeverityCritical, doc.Severity, "recovery failure must outrank the stop that preceded it")
}
