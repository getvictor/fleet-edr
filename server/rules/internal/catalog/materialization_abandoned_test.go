package catalog

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// abandonedCase is one rule whose decision needs the process record an event names, with an event that reaches the resolution
// step on the rule's own payload gates alone. Every rule listed here resolves that record before any other graph read, which is
// what makes its "record still missing past the grace" branch reachable: a rule that walks the graph first gives up earlier, at a
// point that is not a materialization decision, and does not belong in this table.
type abandonedCase struct {
	name  string
	rule  scopedAbandonRule
	event func(ingestedAtNs int64) api.Event
}

// scopedAbandonRule is api.AbandonCounter, so a rule listed here that stopped declaring it fails to compile rather than having
// its abandons stored as not measured.
type scopedAbandonRule = api.AbandonCounter

func abandonedCases() []abandonedCase {
	appControl := func(eventType string) func(int64) api.Event {
		return func(ingestedAtNs int64) api.Event {
			return api.Event{
				EventID:      "abandon-" + eventType,
				HostID:       "fixture-host",
				TimestampNs:  1,
				IngestedAtNs: ingestedAtNs,
				EventType:    eventType,
				Payload:      json.RawMessage(`{"rule_id":"app_control:1","severity":"high","pid":4343}`),
			}
		}
	}
	return []abandonedCase{
		{name: "dns_c2_beacon", rule: &DNSC2Beacon{}, event: dnsC2OutboundConnect},
		{
			name: "suspicious_exec",
			rule: &SuspiciousExec{},
			event: func(ingestedAtNs int64) api.Event {
				return api.Event{
					EventID:      "abandon-suspicious-exec",
					HostID:       "fixture-host",
					TimestampNs:  1,
					IngestedAtNs: ingestedAtNs,
					EventType:    "exec",
					Payload:      json.RawMessage(`{"pid":4242,"path":"/tmp/payload"}`),
				}
			},
		},
		// Resolves the temp exec before walking to an osascript ancestor since issue #1170, which is what put it in this table.
		{
			name: "osascript_network_exec",
			rule: &OsascriptNetworkExec{},
			event: func(ingestedAtNs int64) api.Event {
				return api.Event{
					EventID:      "abandon-osascript",
					HostID:       "fixture-host",
					TimestampNs:  1,
					IngestedAtNs: ingestedAtNs,
					EventType:    "exec",
					Payload:      json.RawMessage(`{"pid":4444,"path":"/tmp/stage2"}`),
				}
			},
		},
		{
			name: "installer_unsigned_package",
			rule: &InstallerUnsignedPackage{},
			event: func(ingestedAtNs int64) api.Event {
				return api.Event{
					EventID:      "abandon-installer-package",
					HostID:       "fixture-host",
					TimestampNs:  1,
					IngestedAtNs: ingestedAtNs,
					EventType:    "exec",
					Payload: json.RawMessage(`{"pid":4545,"path":"/bin/sh","args":["/bin/sh",` +
						`"/tmp/PKInstallSandbox.a/Scripts/p/postinstall","/tmp/x.pkg"],"package_signing":{"signed":false,"notarized":false,"team_id":""}}`),
				}
			},
		},
		{name: "application_control_block", rule: &ApplicationControlBlock{}, event: appControl(applicationControlBlockEventType)},
		{name: "application_control_would_block", rule: &ApplicationControlWouldBlock{}, event: appControl(applicationControlWouldBlockEventType)},
	}
}

// pastEveryGrace is older than both grace windows in play. The flow-process grace is the tighter one, so an age past the subject
// grace is past both, and one value exercises every rule in the table.
func pastEveryGrace() int64 {
	return time.Now().Add(-processMaterializationGrace - time.Minute).UnixNano()
}

// spec:server-detection-rules-engine/evaluations-a-rule-abandons-are-counted/a-rule-that-gives-up-on-a-missing-process-record-is-counted
// spec:server-detection-rules-engine/osascript-waits-for-the-temp-exec-it-judges/a-temp-exec-whose-record-never-arrives-is-counted
//
// The abandon is the branch no other counter sees. Inside the grace a missing record raises the retryable sentinel, which is what
// retryable_misses counts; past it the rule evaluates the event as a non-match. That is the correct decision and also a detection
// that did not happen, so it has to be countable or a rule failing to decide looks exactly like a rule with nothing to report.
func TestMaterializationAbandoned_CountsTheRuleThatGaveUp(t *testing.T) {
	t.Parallel()
	for _, tc := range abandonedCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scope := &api.BatchScope{}
			findings, err := tc.rule.EvaluateScoped(t.Context(), scope, []api.Event{tc.event(pastEveryGrace())}, &recordingGraphReader{})

			require.NoError(t, err, "past the grace the rule must stop waiting, not raise the retryable sentinel")
			assert.Empty(t, findings)
			assert.Equal(t, 1, scope.MaterializationAbandoned(tc.rule.ID()),
				"a rule that evaluated an event as a non-match because its process record never arrived must say so")
		})
	}
}

// spec:server-detection-rules-engine/evaluations-a-rule-abandons-are-counted/a-miss-inside-the-grace-is-a-retry-not-an-abandon
//
// The property that separates the two counters. A young miss is retried and may yet decide the event, so counting it as abandoned
// would report a detection lost that is only late, and would double-count it once the retry did give up.
func TestMaterializationAbandoned_AYoungMissIsARetryNotAnAbandon(t *testing.T) {
	t.Parallel()
	for _, tc := range abandonedCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scope := &api.BatchScope{}
			_, err := tc.rule.EvaluateScoped(t.Context(), scope, []api.Event{tc.event(time.Now().UnixNano())}, &recordingGraphReader{})

			require.ErrorIs(t, err, api.ErrProcessNotYetMaterialized, "inside the grace the rule must wait, not give up")
			assert.Zero(t, scope.MaterializationAbandoned(tc.rule.ID()))
		})
	}
}

// A record that DID materialize is not an abandon however old the event is. Without this case a rule that recorded an abandon on
// every old event, rather than on every old event it could not resolve, would pass the test above.
func TestMaterializationAbandoned_AResolvedProcessIsNotAnAbandon(t *testing.T) {
	t.Parallel()
	for _, tc := range abandonedCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scope := &api.BatchScope{}
			found := &recordingGraphReader{byPID: &api.Process{PID: 4242, Path: "/usr/bin/true"}, byPIDVersion: &api.Process{PID: 4242}}
			_, err := tc.rule.EvaluateScoped(t.Context(), scope, []api.Event{tc.event(pastEveryGrace())}, found)

			require.NoError(t, err)
			assert.Zero(t, scope.MaterializationAbandoned(tc.rule.ID()))
		})
	}
}

// withoutPID is evt with its payload's pid removed, the malformed shape the skip contract names.
func withoutPID(t *testing.T, evt api.Event) api.Event {
	t.Helper()
	var payload map[string]any
	require.NoError(t, json.Unmarshal(evt.Payload, &payload))
	require.Contains(t, payload, "pid", "the fixture must carry a pid for its removal to mean anything")
	delete(payload, "pid")
	stripped, err := json.Marshal(payload)
	require.NoError(t, err)
	evt.Payload = stripped
	return evt
}

// spec:server-detection-rules-engine/an-event-a-rule-cannot-identify-a-subject-for-is-skipped/an-event-carrying-no-process-identifier-is-skipped-rather-than-attributed-to-process-zero
//
// An event with no pid has no subject, so the rule has no process record to wait for or to give up on. Looking up process zero
// would find nothing, and the rule would then count an abandon past the grace, or inside it raise the retryable sentinel on an event
// that no retry can ever resolve. Both inflate the counter this change adds with events that were never decidable.
func TestMaterializationAbandoned_AnEventWithNoPIDIsSkippedNotAbandoned(t *testing.T) {
	t.Parallel()
	for _, tc := range abandonedCases() {
		for _, age := range []struct {
			name       string
			ingestedAt int64
		}{{"past the grace", pastEveryGrace()}, {"inside the grace", time.Now().UnixNano()}} {
			t.Run(tc.name+"/"+age.name, func(t *testing.T) {
				t.Parallel()
				scope := &api.BatchScope{}
				gr := &recordingGraphReader{}
				findings, err := tc.rule.EvaluateScoped(t.Context(), scope, []api.Event{withoutPID(t, tc.event(age.ingestedAt))}, gr)

				require.NoError(t, err)
				assert.Empty(t, findings)
				assert.Zero(t, scope.MaterializationAbandoned(tc.rule.ID()))
				assert.False(t, gr.calledByPID || gr.calledByVersion, "no process lookup is performed for identifier zero")
			})
		}
	}
}
