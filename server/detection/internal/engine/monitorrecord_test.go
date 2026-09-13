package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// recordingMonitorRecords captures the monitor records the engine writes, and the number of writes, and can fail on demand.
type recordingMonitorRecords struct {
	records  []api.Alert
	eventIDs [][]string
	writes   int
	err      error
}

func (r *recordingMonitorRecords) InsertMonitorRecords(_ context.Context, records []mysql.MonitorRecord) error {
	r.writes++
	if r.err != nil {
		return r.err
	}
	for _, rec := range records {
		r.records = append(r.records, rec.Alert)
		r.eventIDs = append(r.eventIDs, rec.EventIDs)
	}
	return nil
}

// modeByRule resolves each rule to the mode named for it, and to alert otherwise.
type modeByRule map[string]rulesapi.DetectionRuleMode

func (m modeByRule) ResolveRuleMode(ruleID, _ string, _ rulesapi.DetectionRuleMode) (rulesapi.DetectionRuleMode, string) {
	if mode, ok := m[ruleID]; ok {
		return mode, ""
	}
	return rulesapi.DetectionRuleModeAlert, ""
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

// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/a-health-signal-rule-in-monitor-mode-keeps-no-record
//
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
	assert.Contains(t, err.Error(), "persist monitor record batch (count=1)")
}

// spec:server-detection-rules-engine/monitor-records-are-written-per-batch/a-batch-s-monitor-records-are-written-together
//
// TestEngine_MonitorRecordsAreWrittenOncePerBatch (issue #1011): every monitor record a batch finds, across rules, reaches the store in
// one write when the batch's evaluation ends, rather than one transaction per finding on the detection path.
func TestEngine_MonitorRecordsAreWrittenOncePerBatch(t *testing.T) {
	t.Parallel()
	records := &recordingMonitorRecords{}
	e := New(nil, discardLogger())
	e.setMonitorRecords(records)
	e.SetModeResolver(overridingResolver{mode: rulesapi.DetectionRuleModeMonitor})
	e.Register(&stubRuleWithFindings{stubRule: stubRule{id: "first"}, findings: []api.Finding{
		{HostID: "h1", RuleID: "first", Severity: "low", Title: "a", ProcessID: 1, EventIDs: []string{"e1"}},
		{HostID: "h1", RuleID: "first", Severity: "low", Title: "b", ProcessID: 2, EventIDs: []string{"e1"}},
	}})
	e.Register(&stubRuleWithFindings{stubRule: stubRule{id: "second"}, findings: []api.Finding{
		{HostID: "h1", RuleID: "second", Severity: "high", Title: "c", ProcessID: 3, EventIDs: []string{"e1"}},
	}})

	_, err := e.Evaluate(t.Context(), monitorBatch())
	require.NoError(t, err)
	assert.Equal(t, 1, records.writes)
	require.Len(t, records.records, 3)
	assert.Equal(t, []int64{1, 2, 3}, []int64{records.records[0].ProcessID, records.records[1].ProcessID, records.records[2].ProcessID},
		"in the order they were found")
}

// spec:server-detection-rules-engine/monitor-records-are-written-per-batch/a-failed-batch-keeps-the-monitor-records-it-found
//
// A batch that ends in an error is nacked, and may be withdrawn for good once its retries run out (#836), so what it found is still
// written: a retryable miss from a later rule and a hard failure both leave the earlier rule's monitor records kept, as they were when
// each was written the moment it was found.
func TestEngine_MonitorRecordsAreWrittenWhenTheBatchFails(t *testing.T) {
	t.Parallel()
	monitorRule := func() *stubRuleWithFindings {
		return &stubRuleWithFindings{stubRule: stubRule{id: "watching"}, findings: []api.Finding{
			{HostID: "host-a", RuleID: "watching", Severity: "low", Title: "t", ProcessID: 9, EventIDs: []string{"e1"}},
		}}
	}
	cases := []struct {
		name  string
		after rulesapi.Rule
		setup func(e *Engine)
		want  error
	}{
		{
			name:  "a later rule's retryable miss",
			after: &failingRule{stubRule: stubRule{id: "racy"}, err: fmt.Errorf("pid 7: %w", rulesapi.ErrProcessNotYetMaterialized)},
			setup: func(*Engine) {},
			want:  rulesapi.ErrProcessNotYetMaterialized,
		},
		{
			name:  "a later rule's failed write",
			after: &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()},
			setup: func(e *Engine) { e.SetHealthEpisodeRecorder(&recordingRecorder{err: errors.New("episode store down")}) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			records := &recordingMonitorRecords{}
			e := New(nil, discardLogger())
			e.setMonitorRecords(records)
			e.SetModeResolver(modeByRule{"watching": rulesapi.DetectionRuleModeMonitor})
			tc.setup(e)
			e.LoadActive(stubProvider{rules: []rulesapi.Rule{monitorRule(), tc.after}})

			_, err := e.Evaluate(t.Context(), healthBatch())
			require.Error(t, err)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want, "the batch's own cause still reaches the processor")
			}
			require.Len(t, records.records, 1)
			assert.Equal(t, "watching", records.records[0].RuleID)
		})
	}
}

// A failed write of the records joins the batch's own cause rather than replacing it, so a retryable miss is still classified as one.
func TestEngine_AFailedMonitorWriteKeepsTheBatchsCause(t *testing.T) {
	t.Parallel()
	e := New(nil, discardLogger())
	e.setMonitorRecords(&recordingMonitorRecords{err: errors.New("records store down")})
	e.SetModeResolver(modeByRule{"watching": rulesapi.DetectionRuleModeMonitor})
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{
		&stubRuleWithFindings{stubRule: stubRule{id: "watching"}, findings: []api.Finding{
			{HostID: "host-a", RuleID: "watching", Severity: "low", Title: "t", ProcessID: 9},
		}},
		&failingRule{stubRule: stubRule{id: "racy"}, err: fmt.Errorf("pid 7: %w", rulesapi.ErrProcessNotYetMaterialized)},
	}})

	_, err := e.Evaluate(t.Context(), healthBatch())
	require.ErrorIs(t, err, rulesapi.ErrProcessNotYetMaterialized)
	assert.ErrorContains(t, err, "records store down")
}
