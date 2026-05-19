//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
)

// TestAppControlBlock_EventBecomesAlert is the cross-context smoke
// for the Application Control demo cut's beat #8: a denied AUTH_EXEC
// on the host ends up as a row in the alerts view that the admin
// can scroll to.
//
// The wiring under test:
//
//   - The agent posts an `application_control_block` event to
//     /api/events (gated by the same host-token middleware as every
//     other event upload).
//   - The detection processor materialises the linked process and
//     evaluates the built-in `application_control_block` catalog rule
//     against the batch.
//   - The rule emits a Finding with Source=application_control.
//   - The engine persists it as an alert; dedup key is
//     (source, host_id, rule_id, process_id) so a repeat block of
//     the same binary by the same rule on the same process collapses
//     into one row.
//
// A regression in any of those steps breaks the demo recording; the
// test exists to catch the regression in CI before the demo dry-run
// catches it on camera.
func TestAppControlBlock_EventBecomesAlert(t *testing.T) {
	t.Parallel()
	stack := Setup(t)

	const hostID = "BBBB1111-2222-3333-4444-555566667777"
	const blockPID = 5151
	hostToken := stepEnroll(t, stack, hostID)

	// Seed a process row the block-event's pid can resolve against. The rule skips events whose pid doesn't materialise into a process row
	// (the graph builder hadn't seen the exec yet), so without the fork/exec pair the block event would land as no-op.
	now := time.Now().UnixNano()
	seedEvents := []detectionapi.Event{
		{
			EventID: "ac-fork", HostID: hostID, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, blockPID)),
		},
		{
			EventID: "ac-exec", HostID: hostID, TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(
				`{"pid":%d,"ppid":1,"path":"/System/Applications/Calculator.app/Contents/MacOS/Calculator","args":["Calculator"]}`,
				blockPID)),
		},
	}
	postEvents(t, stack, hostToken, seedEvents)
	waitForProcess(t, stack, hostID, blockPID)

	// First block event: should produce an alert with
	// source=application_control.
	const ruleID = "app_control:7"
	customMsg := "Blocked: Calculator is not allowed by policy"
	blockEvent := detectionapi.Event{
		EventID:     "ac-block-1",
		HostID:      hostID,
		TimestampNs: now + 2,
		EventType:   "application_control_block",
		Payload: blockPayload(t, blockPayloadInput{
			PID:           blockPID,
			Path:          "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
			RuleID:        ruleID,
			RuleType:      "BINARY",
			Identifier:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Severity:      "high",
			CustomMsg:     &customMsg,
			PolicyID:      11,
			PolicyVersion: 3,
		}),
	}
	postEvents(t, stack, hostToken, []detectionapi.Event{blockEvent})

	var alert detectionapi.Alert
	require.Eventually(t, func() bool {
		alerts, err := stack.DetectionService().ListAlerts(t.Context(), detectionapi.AlertFilter{
			HostID: hostID,
			Source: detectionapi.AlertSourceApplicationControl,
		})
		if err != nil || len(alerts) == 0 {
			return false
		}
		alert = alerts[0]
		return true
	}, 5*time.Second, 50*time.Millisecond, "application control block event must surface as an alert")

	assert.Equal(t, detectionapi.AlertSourceApplicationControl, alert.Source)
	assert.Equal(t, ruleID, alert.RuleID)
	assert.Equal(t, "high", alert.Severity)
	assert.Equal(t, customMsg, alert.Description, "operator's custom_msg is the alert description")
	assert.Contains(t, alert.Title, "Calculator", "alert title should name the blocked binary")

	// Re-post the same block (fresh event_id, same rule+host+process):
	// the alert dedup gate should keep the row count at 1.
	repeat := detectionapi.Event{
		EventID:     "ac-block-2",
		HostID:      hostID,
		TimestampNs: now + 3,
		EventType:   "application_control_block",
		Payload: blockPayload(t, blockPayloadInput{
			PID:           blockPID,
			Path:          "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
			RuleID:        ruleID,
			RuleType:      "BINARY",
			Identifier:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Severity:      "high",
			CustomMsg:     &customMsg,
			PolicyID:      11,
			PolicyVersion: 3,
		}),
	}
	postEvents(t, stack, hostToken, []detectionapi.Event{repeat})

	// Wait long enough for the processor to have observed the second
	// event, then assert dedup held.
	require.Eventually(t, func() bool {
		count, err := stack.DetectionService().ListAlerts(t.Context(), detectionapi.AlertFilter{
			HostID: hostID,
			Source: detectionapi.AlertSourceApplicationControl,
		})
		return err == nil && len(count) == 1
	}, 2*time.Second, 50*time.Millisecond, "repeat block on same (rule, process) must dedup into one alert row")
}

// TestAppControlBlock_DefaultDescriptionWhenCustomMsgAbsent verifies the server-detection-rules-engine spec's default summary
// contract: when the operator did not author a custom_msg, the alert description falls back to "Blocked <rule_type> rule for
// <identifier>".
func TestAppControlBlock_DefaultDescriptionWhenCustomMsgAbsent(t *testing.T) {
	t.Parallel()
	stack := Setup(t)

	const hostID = "CCCC1111-2222-3333-4444-555566667777"
	const blockPID = 6262
	hostToken := stepEnroll(t, stack, hostID)

	now := time.Now().UnixNano()
	postEvents(t, stack, hostToken, []detectionapi.Event{
		{
			EventID: "ac-fork-default", HostID: hostID, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, blockPID)),
		},
		{
			EventID: "ac-exec-default", HostID: hostID, TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":1,"path":"/bin/ls","args":["ls"]}`, blockPID)),
		},
	})
	waitForProcess(t, stack, hostID, blockPID)

	const sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	postEvents(t, stack, hostToken, []detectionapi.Event{{
		EventID:     "ac-block-default",
		HostID:      hostID,
		TimestampNs: now + 2,
		EventType:   "application_control_block",
		Payload: blockPayload(t, blockPayloadInput{
			PID:           blockPID,
			Path:          "/bin/ls",
			RuleID:        "app_control:12",
			RuleType:      "BINARY",
			Identifier:    sha,
			Severity:      "medium",
			PolicyID:      11,
			PolicyVersion: 4,
		}),
	}})

	var alert detectionapi.Alert
	require.Eventually(t, func() bool {
		alerts, err := stack.DetectionService().ListAlerts(t.Context(), detectionapi.AlertFilter{
			HostID: hostID,
			Source: detectionapi.AlertSourceApplicationControl,
		})
		if err != nil || len(alerts) == 0 {
			return false
		}
		alert = alerts[0]
		return true
	}, 5*time.Second, 50*time.Millisecond)

	assert.Equal(t, "Blocked BINARY rule for "+sha, alert.Description,
		"missing custom_msg must fall back to the deterministic default")
}

type blockPayloadInput struct {
	PID           int
	Path          string
	RuleID        string
	RuleType      string
	Identifier    string
	Severity      string
	CustomMsg     *string
	CustomURL     *string
	PolicyID      int64
	PolicyVersion int64
}

// blockPayload renders the JSON shape the extension emits for an application_control_block event. Kept as a local helper so the
// wire-tag contract is exercised by the test rather than imported from production code. Takes *testing.T so a marshal failure
// fails the test loudly instead of slipping a corrupt payload into the event post (would surface downstream as an opaque mismatch
// otherwise).
func blockPayload(t *testing.T, in blockPayloadInput) json.RawMessage {
	t.Helper()
	type wire struct {
		PID           int     `json:"pid"`
		Path          string  `json:"path"`
		RuleID        string  `json:"rule_id"`
		RuleType      string  `json:"rule_type"`
		Identifier    string  `json:"identifier"`
		Severity      string  `json:"severity"`
		CustomMsg     *string `json:"custom_msg,omitempty"`
		CustomURL     *string `json:"custom_url,omitempty"`
		PolicyID      int64   `json:"policy_id"`
		PolicyVersion int64   `json:"policy_version"`
	}
	b, err := json.Marshal(wire{
		PID: in.PID, Path: in.Path,
		RuleID: in.RuleID, RuleType: in.RuleType, Identifier: in.Identifier,
		Severity: in.Severity, CustomMsg: in.CustomMsg, CustomURL: in.CustomURL,
		PolicyID: in.PolicyID, PolicyVersion: in.PolicyVersion,
	})
	require.NoError(t, err)
	return b
}

func postEvents(t *testing.T, stack *Stack, hostToken string, events []detectionapi.Event) {
	t.Helper()
	body, err := json.Marshal(events)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		stack.Server.URL+"/api/events", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+hostToken)
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /api/events status")
}

func waitForProcess(t *testing.T, stack *Stack, hostID string, pid int) {
	t.Helper()
	require.Eventually(t, func() bool {
		p, err := stack.DetectionService().GetProcessDetail(t.Context(), hostID, pid, time.Now().UnixNano())
		return err == nil && p != nil
	}, 5*time.Second, 50*time.Millisecond, "processor must materialise the seed process row")
}

// TestAppControlBlock_EachRuleType_BecomesAlert is the per-rule-type closure for openspec task 11.2.9. The Swift extension's
// decision walker (extension/edr/extension/ApplicationControl/) honours CDHASH, BINARY, SIGNINGID, and TEAMID in Phase A;
// each can produce an application_control_block event. The cross-context pipeline (catalog rule -> engine -> alert insert)
// must turn every shape into a persisted alert without per-type special-casing. A regression where the catalog rule's
// rule_type switch dropped one of the four types (e.g. a missing case label) would silently break detection for that type
// while the existing BINARY-only test stayed green.
//
// One host, one process: the (rule_type, identifier, rule_id) triple varies per subtest so each row has a unique dedup
// key and the alerts table accumulates four independent rows.
func TestAppControlBlock_EachRuleType_BecomesAlert(t *testing.T) {
	t.Parallel()
	stack := Setup(t)

	const hostID = "EEEE1111-2222-3333-4444-555566667777"
	const blockPID = 7373
	hostToken := stepEnroll(t, stack, hostID)

	now := time.Now().UnixNano()
	postEvents(t, stack, hostToken, []detectionapi.Event{
		{
			EventID: "ac-perpath-fork", HostID: hostID, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, blockPID)),
		},
		{
			EventID: "ac-perpath-exec", HostID: hostID, TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(
				`{"pid":%d,"ppid":1,"path":"/usr/local/bin/target","args":["target"]}`, blockPID)),
		},
	})
	waitForProcess(t, stack, hostID, blockPID)

	// Per-type fixtures: the identifier matches the canonical shape the server-side validators accept for that rule_type
	// (CDHASH = 40 lowercase hex, BINARY = 64 lowercase hex, SIGNINGID = platform:bundle OR <TID>:bundle, TEAMID = 10
	// uppercase alphanumeric). Distinct rule_ids so each subtest's alert lands as its own row regardless of dedup.
	cases := []appControlPerTypeCase{
		{"CDHASH", "CDHASH", "cccccccccccccccccccccccccccccccccccccccc", "app_control:101"},
		{"BINARY", "BINARY", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "app_control:102"},
		{"SIGNINGID", "SIGNINGID", "platform:com.apple.curl", "app_control:103"},
		{"TEAMID", "TEAMID", "EQHXZ8M8AV", "app_control:104"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			postBlockEvent(t, stack, hostToken, hostID, blockPID, now+2+int64(i), i, tc)
			waitForAlertByRuleID(t, stack, hostID, tc.ruleID, tc.ruleType)
			assertAlertShape(t, stack, hostID, tc)
		})
	}
}

// postBlockEvent posts a single application_control_block event keyed for the per-rule-type subtest. Extracted
// from the subtest body to keep TestAppControlBlock_EachRuleType_BecomesAlert under Sonar's S3776 cognitive
// complexity threshold; the test's intent is one block-event per rule type and the three helpers spell that
// out without adding meaningful branching inside the subtest closure.
func postBlockEvent(t *testing.T, stack *Stack, hostToken string, hostID string, blockPID int, ts int64, i int,
	tc appControlPerTypeCase,
) {
	t.Helper()
	postEvents(t, stack, hostToken, []detectionapi.Event{{
		EventID:     fmt.Sprintf("ac-perpath-block-%d", i),
		HostID:      hostID,
		TimestampNs: ts,
		EventType:   "application_control_block",
		Payload: blockPayload(t, blockPayloadInput{
			PID:           blockPID,
			Path:          "/usr/local/bin/target",
			RuleID:        tc.ruleID,
			RuleType:      tc.ruleType,
			Identifier:    tc.identifier,
			Severity:      "high",
			PolicyID:      11,
			PolicyVersion: 3,
		}),
	}})
}

// waitForAlertByRuleID polls until an alert with the given rule_id appears for the host. Holds the inner range
// + per-row predicate that otherwise inflates the subtest's cognitive complexity.
func waitForAlertByRuleID(t *testing.T, stack *Stack, hostID string, ruleID string, ruleType string) {
	t.Helper()
	require.Eventually(t, func() bool {
		alerts, err := stack.DetectionService().ListAlerts(t.Context(), detectionapi.AlertFilter{
			HostID: hostID,
			Source: detectionapi.AlertSourceApplicationControl,
		})
		if err != nil {
			return false
		}
		return findAlertByRuleID(alerts, ruleID) != nil
	}, 5*time.Second, 50*time.Millisecond, "block event with rule_type=%s must surface as an alert", ruleType)
}

// assertAlertShape pins source / severity / default-description so a regression that drops rule_type from the
// wire payload or mis-maps the default-description fallback surfaces here rather than at demo time.
func assertAlertShape(t *testing.T, stack *Stack, hostID string, tc appControlPerTypeCase) {
	t.Helper()
	alerts, err := stack.DetectionService().ListAlerts(t.Context(), detectionapi.AlertFilter{
		HostID: hostID,
		Source: detectionapi.AlertSourceApplicationControl,
	})
	require.NoError(t, err)
	got := findAlertByRuleID(alerts, tc.ruleID)
	require.NotNil(t, got, "alert for rule_id=%s should exist after Eventually returned true", tc.ruleID)
	assert.Equal(t, detectionapi.AlertSourceApplicationControl, got.Source)
	assert.Equal(t, "high", got.Severity)
	assert.Equal(t, "Blocked "+tc.ruleType+" rule for "+tc.identifier, got.Description,
		"default description for this rule_type must include the identifier")
}

// findAlertByRuleID returns the first alert in the slice whose RuleID matches, or nil. Centralises the linear
// scan so the test helpers don't repeat the indexed-range pattern.
func findAlertByRuleID(alerts []detectionapi.Alert, ruleID string) *detectionapi.Alert {
	for i := range alerts {
		if alerts[i].RuleID == ruleID {
			return &alerts[i]
		}
	}
	return nil
}

// appControlPerTypeCase is the per-subtest fixture shape shared across the helpers above. Kept as a named
// type rather than an anonymous struct so the helper signatures stay readable.
type appControlPerTypeCase struct {
	name       string
	ruleType   string
	identifier string
	ruleID     string
}
