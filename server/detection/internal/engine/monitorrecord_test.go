package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// recordingMonitorRecords captures the monitor records the engine writes, and can fail on demand.
type recordingMonitorRecords struct {
	records  []api.Alert
	eventIDs [][]string
	err      error
}

func (r *recordingMonitorRecords) InsertAlert(_ context.Context, a api.Alert, eventIDs []string) (int64, bool, error) {
	if r.err != nil {
		return 0, false, r.err
	}
	r.records = append(r.records, a)
	r.eventIDs = append(r.eventIDs, eventIDs)
	return int64(len(r.records)), true, nil
}

func monitorBatch() []api.Event {
	return []api.Event{{EventID: "e1", HostID: "h1", EventType: "exec", Platform: "darwin"}}
}

// TestEngine_MonitorFindingIsKeptAsAMonitorRecord pins what the monitor route writes (issue #994): the row an alert would have been,
// marked as a monitor record. The severity override is applied so the record and the monitor counter describe the match at the same
// severity, which is the comparison the counter exists for. The nil store proves nothing took the alert path, which would panic.
func TestEngine_MonitorFindingIsKeptAsAMonitorRecord(t *testing.T) {
	t.Parallel()
	records := &recordingMonitorRecords{}
	e := New(nil, discardLogger())
	e.setMonitorRecords(records)
	e.SetModeResolver(overridingResolver{mode: rulesapi.DetectionRuleModeMonitor, severity: "critical"})
	e.Register(&stubRuleWithFindings{
		stubRule: stubRule{id: "imported", techniques: []string{"T1059"}},
		findings: []api.Finding{{
			HostID: "h1", RuleID: "imported", Severity: "low", Title: "t", Description: "d", ProcessID: 42, EventIDs: []string{"e1"},
		}},
	})

	tally, err := e.Evaluate(t.Context(), monitorBatch())
	require.NoError(t, err)

	require.Len(t, records.records, 1, "one monitor record for the one finding")
	got := records.records[0]
	assert.Equal(t, api.AlertDispositionMonitor, got.Disposition)
	assert.Equal(t, api.AlertSourceDetection, got.Source)
	assert.Equal(t, "critical", got.Severity, "the record carries the severity the counter is labelled with")
	assert.Equal(t, int64(42), got.ProcessID)
	assert.Equal(t, api.JSONStringSlice{"T1059"}, got.Techniques, "the rule's techniques fill in, as for an alert")
	assert.Equal(t, []string{"e1"}, records.eventIDs[0])
	require.Len(t, tally, 1, "and the match is still counted")
}

// TestEngine_MonitorHealthRuleKeepsNoRecord: a health-signal rule in monitor mode is counted and keeps no record. Its findings are
// host health episodes when it records anything (issue #778), so a monitor record would put an operational fault in the alerts table.
func TestEngine_MonitorHealthRuleKeepsNoRecord(t *testing.T) {
	t.Parallel()
	records := &recordingMonitorRecords{}
	e := New(nil, discardLogger())
	e.setMonitorRecords(records)
	e.SetModeResolver(overridingResolver{mode: rulesapi.DetectionRuleModeMonitor})
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	tally, err := e.Evaluate(t.Context(), healthBatch())
	require.NoError(t, err)
	assert.Empty(t, records.records)
	require.Len(t, tally, 1, "the match is still counted")
}

// TestEngine_MonitorRecordFailureFailsTheBatch: a failed write is returned, as a failed alert write is, so the batch is retried rather
// than the record silently lost. The retry's write is a no-op for anything the failed attempt committed, because of the dedup key.
func TestEngine_MonitorRecordFailureFailsTheBatch(t *testing.T) {
	t.Parallel()
	e := New(nil, discardLogger())
	e.setMonitorRecords(&recordingMonitorRecords{err: errors.New("boom")})
	e.SetModeResolver(overridingResolver{mode: rulesapi.DetectionRuleModeMonitor})
	e.Register(&stubRuleWithFindings{
		stubRule: stubRule{id: "imported"},
		findings: []api.Finding{{HostID: "h1", RuleID: "imported", Severity: "high", Title: "t", ProcessID: 1}},
	})

	err := evaluateErr(e, t.Context(), monitorBatch())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist monitor record for rule imported")
}
