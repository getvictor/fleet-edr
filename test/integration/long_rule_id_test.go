//go:build integration

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// longRuleID is the longest identifier the catalog ships, at 70 characters, and the reason issue #832 exists. It comes from an
// upstream SigmaHQ filename rather than anything this repo chose.
const longRuleID = "proc_creation_macos_remote_access_tools_teamviewer_incoming_connection"

// spec:server-detection-rules-engine/a-rule-whose-identifier-cannot-be-persisted-is-refused-at-load/a-rule-with-a-long-identifier-can-raise-an-alert
//
// TestLongRuleID_PromotedRuleAlertsWithoutWedgingTheQueue reproduces issue #832 end to end and pins that it is fixed.
//
// Every rule_id column was VARCHAR(64) while this rule's identifier is 70 characters, and MySQL in strict mode rejects rather than
// truncates. The consequence was not a missing alert, it was a stalled host: alert persistence is deliberately not isolated per
// rule, so the failed insert failed the batch, the batch was nacked and re-claimed, and nothing caps the attempts. Detection for
// that host stopped entirely, for every rule, until someone noticed.
//
// It needed exactly one operator action to trigger, which is why this test performs that action rather than a synthetic one. All
// 55 imported rules ship in monitor mode, where the alert is suppressed before it reaches the table, and #813 exists specifically
// to help an operator promote them. So promotion is the documented workflow, not an edge case.
//
// The promotion itself is also part of the coverage: detection_rule_settings.rule_id was one of the four narrow columns, so before
// the widening the INSERT below fails and the rule cannot even be promoted.
func TestLongRuleID_PromotedRuleAlertsWithoutWedgingTheQueue(t *testing.T) {
	t.Parallel()
	stack := Setup(t)
	ctx := t.Context()

	const hostID = "DDDD1111-2222-3333-4444-555566667777"
	hostToken := stepEnroll(t, stack, hostID)

	// Promote the rule out of monitor. Written straight to the table rather than through REST for the same reason the efficacy
	// harness does: the promotion is a precondition here, not the behaviour under test. The version bump is the cache-invalidation
	// signal rather than bookkeeping, because a replica reloads its config snapshot only when detection_config_meta.version moves.
	_, err := stack.DB.ExecContext(ctx, `
		INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, updated_by)
		VALUES (?, 0, 'alert', 'issue-832-test')
		ON DUPLICATE KEY UPDATE mode = VALUES(mode)`, longRuleID)
	require.NoError(t, err,
		"a 70-character identifier must fit detection_rule_settings.rule_id, or the rule cannot be promoted at all")
	_, err = stack.DB.ExecContext(ctx, `UPDATE detection_config_meta SET version = version + 1 WHERE id = 1`)
	require.NoError(t, err)

	// Setup does not start the rules context's refresh loop, so without this the config stays frozen at whatever boot loaded and
	// the rule evaluates in monitor mode. t.Context cancels it with the test.
	go stack.Rules.Run(ctx)

	resolver := stack.Rules.DetectionConfigModeResolver()
	require.Eventually(t, func() bool {
		mode, _ := resolver.ResolveRuleMode(longRuleID, hostID, rulesapi.DetectionRuleModeMonitor)
		return mode == rulesapi.DetectionRuleModeAlert
	}, 30*time.Second, 100*time.Millisecond,
		"the promotion never reached the server's config snapshot, so the rule would still be in monitor and suppress its alert")

	// The event shape the rule matches, taken from its own committed fixture: TeamViewer_Service spawning TeamViewer_Desktop with
	// the incoming-connection arguments.
	now := time.Now().UnixNano()
	postEvents(t, stack, hostToken, []detectionapi.Event{
		{
			EventID: "tv-parent-fork", HostID: hostID, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":4800,"parent_pid":1}`),
		},
		{
			EventID: "tv-parent-exec", HostID: hostID, TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":4800,"ppid":1,` +
				`"path":"/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Service",` +
				`"args":["TeamViewer_Service"],"uid":501,"gid":20}`),
		},
		{
			EventID: "tv-fork", HostID: hostID, TimestampNs: now + 2, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":4900,"parent_pid":4800}`),
		},
		{
			EventID: "tv-exec", HostID: hostID, TimestampNs: now + 3, EventType: "exec",
			Payload: json.RawMessage(`{"pid":4900,"ppid":4800,` +
				`"path":"/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Desktop",` +
				`"args":["/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Desktop","--IPCport","5939","--Module","1"],` +
				`"uid":501,"gid":20}`),
		},
	})

	// The alert persists, which is the half that failed outright before.
	require.Eventually(t, func() bool {
		alerts, listErr := stack.DetectionService().ListAlerts(ctx, detectionapi.AlertFilter{HostID: hostID})
		if listErr != nil {
			return false
		}
		for _, a := range alerts {
			if a.RuleID == longRuleID {
				return true
			}
		}
		return false
	}, 20*time.Second, 100*time.Millisecond,
		"the promoted rule raised no alert: a 70-character identifier must round-trip through alerts.rule_id")

	// And the batch is ACKNOWLEDGED, which is the half that made this an outage rather than a missing alert. A failed insert
	// nacks, and the nack has no attempt cap, so the same events are re-claimed forever and the host stops draining. Asserted on
	// the queue rather than inferred from the alert, because an alert could in principle be written by an attempt that then
	// failed on a later finding and still nacked.
	require.Eventually(t, func() bool {
		var unacked int
		if qErr := stack.DB.GetContext(ctx, &unacked,
			`SELECT COUNT(*) FROM event_queue WHERE host_id = ? AND processed <> 1`, hostID); qErr != nil {
			return false
		}
		return unacked == 0
	}, 20*time.Second, 100*time.Millisecond,
		"events stayed unacknowledged, which is the signature of the wedge: the batch is nacked, re-claimed and fails again "+
			"with nothing capping the attempts, so detection for this host stops for every rule and not just this one")

	// One alert, not one per replay. If the queue were still cycling, dedup would hide it in the alert list but the row count
	// would not: alert dedup keys on (source, host, rule, subject), so a wedged queue shows up as an unacknowledged queue rather
	// than duplicate alerts. Asserted so a future change to dedup cannot quietly turn a wedge into a flood.
	var alertRows int
	require.NoError(t, stack.DB.GetContext(ctx, &alertRows,
		`SELECT COUNT(*) FROM alerts WHERE host_id = ? AND rule_id = ?`, hostID, longRuleID))
	assert.Equal(t, 1, alertRows, "the match should have produced exactly one alert row")
}
