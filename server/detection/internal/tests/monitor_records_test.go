//go:build integration

// Integration coverage for monitor records (issue #994), against real MySQL: a monitor-mode match is kept as a readable record rather
// than only counted, it stays out of everything that makes a row an alert, and promoting its rule raises an alert for a finding the rule
// already matched in monitor.

package tests

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// monitorRecordsFor lists hostID's monitor records, keyed by rule.
func monitorRecordsFor(ctx context.Context, t *testing.T, d *bootstrap.Detection, hostID string) map[string]api.Alert {
	t.Helper()
	records, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: hostID, Disposition: api.AlertDispositionMonitor})
	require.NoError(t, err)
	m := make(map[string]api.Alert, len(records))
	for _, r := range records {
		m[r.RuleID] = r
	}
	return m
}

// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/a-monitor-mode-match-is-kept-as-a-monitor-record
// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/an-alert-mode-match-is-not-also-kept-as-a-monitor-record
// spec:server-rest-api/filterable-alerts-list/the-list-excludes-monitor-records-unless-they-are-asked-for
//
// TestMonitorRecords_KeepsAMonitorMatchAsARecordNotAnAlert runs one rule in each mode against the same batch. The alert-mode rule is also
// the barrier: once its alert exists the batch has been evaluated, so the absences asserted below are sound rather than racy.
func TestMonitorRecords_KeepsAMonitorMatchAsARecordNotAnAlert(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	d.LoadActive(stubProvider{rules: []rulesapi.Rule{
		&stubRule{id: "stub-alert", techniques: []string{"T9999"}},
		&stubRule{id: "stub-monitor", techniques: []string{"T9999"}},
	}})
	d.SetModeResolver(fakeMode{resolve: func(ruleID, _ string) (rulesapi.DetectionRuleMode, string) {
		if ruleID == "stub-monitor" {
			return rulesapi.DetectionRuleModeMonitor, ""
		}
		return rulesapi.DetectionRuleModeAlert, ""
	}})

	procID := mustInsertProcess(t, ctx, d, "host-m", 100)
	insertEventsViaIngest(ctx, t, d, "host-m", []api.Event{
		{EventID: "trigger-m", HostID: "host-m", TimestampNs: 2000, EventType: "trigger", Payload: json.RawMessage(`{"pid":100}`)},
	})

	require.Eventually(t, func() bool {
		alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-m"})
		return err == nil && len(alerts) == 1 && len(monitorRecordsFor(ctx, t, d, "host-m")) == 1
	}, 10*time.Second, 50*time.Millisecond, "one alert from the alert-mode rule and one monitor record from the monitor-mode rule")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-m"})
	require.NoError(t, err)
	require.Len(t, alerts, 1, "the default list holds alerts only")
	assert.Equal(t, "stub-alert", alerts[0].RuleID)
	assert.Equal(t, api.AlertDispositionAlert, alerts[0].Disposition)

	byRule, err := d.Service().ListAlerts(ctx, api.AlertFilter{Disposition: api.AlertDispositionMonitor, RuleID: "stub-monitor"})
	require.NoError(t, err)
	require.Len(t, byRule, 1, "a rule's monitor records can be listed by rule, which is the console's way in from its Observed figure")
	noneForAlertRule, err := d.Service().ListAlerts(ctx, api.AlertFilter{Disposition: api.AlertDispositionMonitor, RuleID: "stub-alert"})
	require.NoError(t, err)
	assert.Empty(t, noneForAlertRule, "and the rule filter selects only that rule's")

	records := monitorRecordsFor(ctx, t, d, "host-m")
	require.Contains(t, records, "stub-monitor")
	assert.NotContains(t, records, "stub-alert", "an alert-mode finding is not also kept as a monitor record")

	record := records["stub-monitor"]
	assert.Equal(t, api.AlertDispositionMonitor, record.Disposition)
	assert.Equal(t, rulesapi.SeverityHigh, record.Severity)
	assert.Equal(t, "Triggered", record.Title)
	assert.Equal(t, "stub rule fired", record.Description)
	assert.Equal(t, procID, record.ProcessID, "the process link an operator pivots from")
	assert.Equal(t, api.JSONStringSlice{"T9999"}, record.Techniques)

	detail, eventIDs, err := d.Service().GetAlert(ctx, record.ID)
	require.NoError(t, err)
	assert.Equal(t, api.AlertDispositionMonitor, detail.Disposition, "the detail read reports the disposition too")
	assert.Equal(t, []string{"trigger-m"}, eventIDs, "the triggering event is linked")
	evidence, err := d.Service().GetAlertEvidence(ctx, record.ID)
	require.NoError(t, err)
	require.Len(t, evidence, 1, "and its evidence is copied, as for an alert")
	assert.Equal(t, "trigger-m", evidence[0].EventID)
}

// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/promotion-raises-an-alert-for-an-already-recorded-finding
// spec:server-detection-rules-engine/alert-dedup-by-subject/an-alert-and-a-monitor-record-for-one-finding-are-separate-records
//
// TestMonitorRecords_PromotionRaisesAnAlertForAFindingAlreadyRecorded is the reason disposition is in the dedup key. The stub rule reports
// the same subject (process 1) for every trigger, so the finding after promotion collides with the monitor record on every other column
// of the key. Without disposition in it, the alert insert is absorbed by the monitor record and promotion raises nothing.
func TestMonitorRecords_PromotionRaisesAnAlertForAFindingAlreadyRecorded(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	var promoted atomic.Bool
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "stub-promoted"}}})
	d.SetModeResolver(fakeMode{resolve: func(string, string) (rulesapi.DetectionRuleMode, string) {
		if promoted.Load() {
			return rulesapi.DetectionRuleModeAlert, ""
		}
		return rulesapi.DetectionRuleModeMonitor, ""
	}})

	mustInsertProcess(t, ctx, d, "host-p", 100)
	insertEventsViaIngest(ctx, t, d, "host-p", []api.Event{
		{EventID: "trigger-before", HostID: "host-p", TimestampNs: 2000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})
	require.Eventually(t, func() bool { return len(monitorRecordsFor(ctx, t, d, "host-p")) == 1 },
		10*time.Second, 50*time.Millisecond, "the match before promotion is kept as a monitor record")
	before := monitorRecordsFor(ctx, t, d, "host-p")["stub-promoted"]

	promoted.Store(true)
	insertEventsViaIngest(ctx, t, d, "host-p", []api.Event{
		{EventID: "trigger-after", HostID: "host-p", TimestampNs: 3000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})

	var alerts []api.Alert
	require.Eventually(t, func() bool {
		var err error
		alerts, err = d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-p"})
		return err == nil && len(alerts) == 1
	}, 10*time.Second, 50*time.Millisecond, "the same finding after promotion raises an alert")
	assert.NotEqual(t, before.ID, alerts[0].ID, "the alert is its own row, not the monitor record")

	after, eventIDs, err := d.Service().GetAlert(ctx, before.ID)
	require.NoError(t, err)
	assert.Equal(t, api.AlertDispositionMonitor, after.Disposition, "promotion does not rewrite the stored record")
	assert.True(t, before.UpdatedAt.Equal(after.UpdatedAt), "and does not touch it")
	assert.Equal(t, []string{"trigger-before"}, eventIDs, "the post-promotion evidence went to the alert, not to the record")
}

// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/a-monitor-record-is-not-notified-or-triaged
//
// TestMonitorRecords_AreNotNotified pins the webhook gate at the store, where it lives, with a destination that would take any new
// detection alert. The alert of the same shape is what makes the absence meaningful: it shows the destination does match.
func TestMonitorRecords_AreNotNotified(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	makeDest(t, store, "every-alert", api.SeverityLow, true, api.WebhookEventAlertCreated)

	monitor := highAlert("proc:7")
	monitor.Disposition = api.AlertDispositionMonitor
	monitorID, created, err := store.InsertAlert(t.Context(), monitor, nil)
	require.NoError(t, err)
	require.True(t, created)
	assert.Empty(t, allDeliveries(t, db), "a new monitor record enqueues no delivery")

	alertID, created, err := store.InsertAlert(t.Context(), highAlert("proc:7"), nil)
	require.NoError(t, err)
	require.True(t, created, "an alert for the same finding is a new row, because disposition is in the dedup key")
	assert.NotEqual(t, monitorID, alertID)
	assert.Len(t, allDeliveries(t, db), 1, "while the alert of the same shape does reach the destination")
}

// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/a-monitor-record-is-not-notified-or-triaged
// spec:server-rest-api/update-alert-lifecycle-status/a-status-change-addressed-to-a-monitor-record-is-rejected
//
// TestMonitorRecords_AreNotTriaged goes through the service, where the refusal is made. updated_at is checked as well as status, because a
// status write that was refused but still refreshed the row would restart the record's retention clock.
func TestMonitorRecords_AreNotTriaged(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	monitor := highAlert("proc:8")
	monitor.Disposition = api.AlertDispositionMonitor
	id, _, err := d.Store().InsertAlert(ctx, monitor, nil)
	require.NoError(t, err)
	before, _, err := d.Service().GetAlert(ctx, id)
	require.NoError(t, err)

	_, err = d.Service().UpdateAlertStatus(ctx, id, api.AlertStatusAcknowledged, "")
	require.ErrorIs(t, err, api.ErrInvalidAlertTransition, "a status change addressed to a monitor record is refused")

	after, _, err := d.Service().GetAlert(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.AlertStatusOpen, after.Status)
	assert.True(t, before.UpdatedAt.Equal(after.UpdatedAt), "and the refused change did not refresh the row")
}
