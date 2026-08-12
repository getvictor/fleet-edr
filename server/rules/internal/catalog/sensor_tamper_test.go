package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// transitionArchive is a GraphReader whose only real method is the transition lookup: it returns the recorded events for
// (host, type) that fall inside the requested window, the same filtering the archive does, so a test's window arithmetic
// is exercised rather than stubbed past. It also records the windows it was asked for, because the window bounds are
// half of what this rule is.
type transitionArchive struct {
	events    []api.Event
	windows   []api.TimeRange
	lookupErr error
}

func (a *transitionArchive) GetHostEventsByType(
	_ context.Context, hostID, eventType string, tr api.TimeRange,
) ([]api.Event, error) {
	a.windows = append(a.windows, tr)
	if a.lookupErr != nil {
		return nil, a.lookupErr
	}
	var out []api.Event
	for _, e := range a.events {
		if e.HostID != hostID || e.EventType != eventType {
			continue
		}
		if e.TimestampNs < tr.FromNs || e.TimestampNs > tr.ToNs {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (a *transitionArchive) GetProcessByPID(context.Context, string, int, int64) (*api.Process, error) {
	return nil, nil
}

func (a *transitionArchive) GetProcessByPIDVersion(
	context.Context, string, int, uint32, int64,
) (*api.Process, error) {
	return nil, nil
}

func (a *transitionArchive) GetChildProcesses(
	context.Context, string, int, api.TimeRange,
) ([]api.Process, error) {
	return nil, nil
}

func (a *transitionArchive) GetExecChain(context.Context, api.Process) ([]api.Process, error) {
	return nil, nil
}

func (a *transitionArchive) GetNetworkEventsForProcess(
	context.Context, string, int, api.TimeRange,
) ([]api.Event, error) {
	return nil, nil
}

const tamperHost = "AAAA1562-0001-0000-0000-000000000001"

// transitionEvent builds a sensor_provider_transition event. ingestAge is how long ago the server accepted it, which is
// what decides whether an unanswered stop is still waiting on its recovery window or has run out of patience.
func transitionEvent(id, provider, state string, atNs int64, ingestAge time.Duration, stopReason *int) api.Event {
	payload := map[string]any{"provider": provider, "state": state}
	if stopReason != nil {
		payload["stop_reason"] = *stopReason
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return api.Event{
		EventID:      id,
		HostID:       tamperHost,
		EventType:    "sensor_provider_transition",
		TimestampNs:  atNs,
		IngestedAtNs: time.Now().Add(-ingestAge).UnixNano(),
		Payload:      raw,
	}
}

// TestSensorTamper_DiscriminatesUpgradeFromTamper is the test this rule exists for. Both inputs are a stopped
// content_filter carrying platform reason 1 (userInitiated): measured on a live host, a routine system-extension cutover
// produces exactly the same stop as somebody switching capture off, so the ONLY thing separating them is how fast
// capture resumes. The gaps here are the measured ones (1.1s for the cutover, 32s for a tamper the self-heal repaired).
//
// spec:server-detection-rules-engine/edr-sensor-tamper-detection/a-capture-provider-stops-and-does-not-resume
// spec:server-detection-rules-engine/edr-sensor-tamper-detection/an-upgrade-cutover-does-not-fire
func TestSensorTamper_DiscriminatesUpgradeFromTamper(t *testing.T) {
	t.Parallel()
	const stopNs = int64(1_000_000_000_000)

	cases := []struct {
		name        string
		recoveryGap time.Duration
		wantFinding bool
	}{
		{"upgrade cutover: capture resumes in 1.1s", 1100 * time.Millisecond, false},
		{"tamper: capture resumes only after the self-heal, 32s later", 32 * time.Second, true},
		{"tamper: capture never resumes at all", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stop := transitionEvent("stop-1", "content_filter", "stopped", stopNs, 30*time.Second, new(1))
			archive := &transitionArchive{events: []api.Event{stop}}
			if tc.recoveryGap > 0 {
				archive.events = append(archive.events, transitionEvent(
					"run-1", "content_filter", "running", stopNs+tc.recoveryGap.Nanoseconds(), 30*time.Second, nil))
			}

			findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{stop}, archive)
			require.NoError(t, err)

			if !tc.wantFinding {
				assert.Empty(t, findings, "a stop whose capture resumed inside the window must not alert")
				return
			}
			require.Len(t, findings, 1)
			assert.Equal(t, "sensor_tamper", findings[0].RuleID)
			assert.Equal(t, api.SeverityHigh, findings[0].Severity)
			assert.Equal(t, tamperHost, findings[0].HostID)
			assert.Equal(t, []string{"stop-1"}, findings[0].EventIDs, "the alert must cite the stop it fired on")
			assert.Contains(t, findings[0].Description, "content_filter")
			assert.Contains(t, findings[0].Description, "stop reason 1",
				"the platform reason belongs in the alert even though the rule does not judge on it")
		})
	}
}

// TestSensorTamper_RecoveryWindowIsBoundedToTheStop pins the lookup window itself. A rule that asked for an unbounded range would suppress
// on ANY past recovery, including one that predates the stop, which would make a provider that is stopped right now look repaired.
func TestSensorTamper_RecoveryWindowIsBoundedToTheStop(t *testing.T) {
	t.Parallel()
	const stopNs = int64(1_000_000_000_000)
	stop := transitionEvent("stop-1", "content_filter", "stopped", stopNs, 30*time.Second, new(1))
	// A running transition from BEFORE the stop: the provider was up, then someone switched it off. Suppressing on this
	// would invert the rule.
	earlier := transitionEvent("run-earlier", "content_filter", "running", stopNs-time.Second.Nanoseconds(),
		30*time.Second, nil)
	archive := &transitionArchive{events: []api.Event{earlier, stop}}

	findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{stop}, archive)
	require.NoError(t, err)
	assert.Len(t, findings, 1, "a recovery that predates the stop is not a recovery from it")

	require.Len(t, archive.windows, 1)
	assert.Equal(t, stopNs, archive.windows[0].FromNs, "the window must start at the stop, not before it")
	assert.Equal(t, stopNs+(5*time.Second).Nanoseconds(), archive.windows[0].ToNs)
}

// TestSensorTamper_RecoveryMustBeTheSameProvider: the two providers fail independently, so one coming back says nothing
// about the other. Without the provider comparison, disabling the content filter would be masked by any DNS-proxy
// activity that happened to land in the same five seconds.
func TestSensorTamper_RecoveryMustBeTheSameProvider(t *testing.T) {
	t.Parallel()
	const stopNs = int64(1_000_000_000_000)
	stop := transitionEvent("stop-1", "content_filter", "stopped", stopNs, 30*time.Second, new(1))
	otherProvider := transitionEvent("run-dns", "dns_proxy", "running", stopNs+time.Second.Nanoseconds(),
		30*time.Second, nil)
	archive := &transitionArchive{events: []api.Event{stop, otherProvider}}

	findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{stop}, archive)
	require.NoError(t, err)
	assert.Len(t, findings, 1, "another provider starting does not mean this one recovered")
}

// TestSensorTamper_WaitsForTheWindowBeforeDeciding covers the timing half of the rule. A stop is evaluated within
// milliseconds of arriving, long before its recovery could have been uploaded, so an early "no recovery found" is not an
// answer. Inside the grace the rule must ask for the batch again; past it, it must decide rather than retry forever.
//
// spec:server-detection-rules-engine/edr-sensor-tamper-detection/a-stop-is-not-judged-before-its-recovery-window-elapses
func TestSensorTamper_WaitsForTheWindowBeforeDeciding(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		ingestAge   time.Duration
		wantRetry   bool
		wantFinding int
	}{
		{"just arrived: the recovery could still be in flight", 100 * time.Millisecond, true, 0},
		{"inside the grace", 7 * time.Second, true, 0},
		{"past the grace: no recovery is coming", 30 * time.Second, false, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stop := transitionEvent("stop-1", "content_filter", "stopped", time.Now().UnixNano(), tc.ingestAge, new(1))
			archive := &transitionArchive{events: []api.Event{stop}}

			findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{stop}, archive)
			assert.Len(t, findings, tc.wantFinding)
			if tc.wantRetry {
				require.Error(t, err)
				assert.ErrorIs(t, err, api.ErrProcessNotYetMaterialized,
					"an undecided stop must ask for the batch again rather than alerting early")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestSensorTamper_IgnoresEverythingItIsNotAbout. The rule sees every event in the batch, and a rule that fired on a
// running transition or on an unrelated event type would alert on ordinary agent startup.
func TestSensorTamper_IgnoresEverythingItIsNotAbout(t *testing.T) {
	t.Parallel()
	const atNs = int64(1_000_000_000_000)
	cases := []struct {
		name  string
		event api.Event
	}{
		{"a provider starting", transitionEvent("run-1", "content_filter", "running", atNs, 30*time.Second, nil)},
		{"an unrelated event type", api.Event{
			EventID: "open-1", HostID: tamperHost, EventType: "open", TimestampNs: atNs,
			IngestedAtNs: time.Now().UnixNano(), Payload: json.RawMessage(`{"pid":1,"path":"/etc/sudoers","flags":1}`),
		}},
		{"a transition whose payload is not readable", api.Event{
			EventID: "bad-1", HostID: tamperHost, EventType: "sensor_provider_transition", TimestampNs: atNs,
			IngestedAtNs: time.Now().UnixNano(), Payload: json.RawMessage(`{"provider":`),
		}},
		{"a stop naming no provider", transitionEvent("stop-none", "", "stopped", atNs, 30*time.Second, new(1))},
		{"a state from a newer agent this server does not know", transitionEvent(
			"odd-1", "content_filter", "reconfiguring", atNs, 30*time.Second, nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			archive := &transitionArchive{events: []api.Event{tc.event}}
			findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{tc.event}, archive)
			require.NoError(t, err)
			assert.Empty(t, findings)
			assert.Empty(t, archive.windows, "an event the rule is not about must not cost an archive read")
		})
	}
}

// TestSensorTamper_ADisabledProviderIsInvisible. Turning the optional DNS proxy off is a supported configuration, and an
// operator who did it must not be alerted about it daily. The rule needs no suppression list for that: the agent reports
// a deliberate opt-out as the provider being ABSENT rather than stopped and records no transition for it, so the batch
// reaching the engine carries nothing about that provider at all. This pins the consequence, that a host running one
// provider deliberately is silent rather than merely low-severity.
//
// spec:server-detection-rules-engine/edr-sensor-tamper-detection/a-deliberately-disabled-provider-does-not-fire
func TestSensorTamper_ADisabledProviderIsInvisible(t *testing.T) {
	t.Parallel()
	const atNs = int64(1_000_000_000_000)
	// What the wire actually carries for a host whose operator disabled the DNS proxy: transitions for the provider that
	// is running, and no record whatsoever for the disabled one.
	batch := []api.Event{transitionEvent("run-cf", "content_filter", "running", atNs, 30*time.Second, nil)}
	archive := &transitionArchive{events: batch}

	findings, err := (&SensorTamper{}).Evaluate(context.Background(), batch, archive)
	require.NoError(t, err)
	assert.Empty(t, findings, "a supported opt-out must produce no alert at all")
}

// TestSensorTamper_AnUnreadableNeighbourDoesNotHideTheRecovery. The window can contain events this server cannot parse:
// a newer agent, or a truncated payload. Abandoning the scan on the first of those would report a tamper on a host whose
// capture actually resumed, which is the expensive direction to be wrong in, because it fires on every upgrade.
func TestSensorTamper_AnUnreadableNeighbourDoesNotHideTheRecovery(t *testing.T) {
	t.Parallel()
	const stopNs = int64(1_000_000_000_000)
	stop := transitionEvent("stop-1", "content_filter", "stopped", stopNs, 30*time.Second, new(1))
	unreadable := api.Event{
		EventID: "garbled", HostID: tamperHost, EventType: "sensor_provider_transition",
		TimestampNs: stopNs + int64(500*time.Millisecond), IngestedAtNs: time.Now().UnixNano(),
		Payload: json.RawMessage(`{"provider":`),
	}
	resume := transitionEvent("run-1", "content_filter", "running", stopNs+int64(time.Second), 30*time.Second, nil)
	archive := &transitionArchive{events: []api.Event{stop, unreadable, resume}}

	findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{stop}, archive)
	require.NoError(t, err)
	assert.Empty(t, findings, "the readable recovery behind the unreadable event must still be found")
}

// TestSensorTamper_DedupSubjectIsPerStop. The alert has no process to hang dedup on, so it supplies its own subject. Re-evaluating one stop
// (which the retry path does by design) must collapse; a later, separate stop must not, or a tamper today would be silently swallowed by an
// alert from last month.
func TestSensorTamper_DedupSubjectIsPerStop(t *testing.T) {
	t.Parallel()
	first := sensorTamperSubject("content_filter", "stop-1")
	assert.Equal(t, first, sensorTamperSubject("content_filter", "stop-1"), "the same stop must dedup onto itself")
	assert.NotEqual(t, first, sensorTamperSubject("content_filter", "stop-2"), "a separate stop is a separate alert")
	assert.NotEqual(t, first, sensorTamperSubject("dns_proxy", "stop-1"), "providers must not collide")
	assert.NotEmpty(t, first, "a process-less alert with a blank subject is rejected by the store")
}

// TestSensorTamper_LookupFailureIsNotSilence. A broken archive read must surface, not be mistaken for "nothing
// recovered" (which would alert on every upgrade) or for "recovered" (which would suppress every tamper).
func TestSensorTamper_LookupFailureIsNotSilence(t *testing.T) {
	t.Parallel()
	stop := transitionEvent("stop-1", "content_filter", "stopped", 1_000_000_000_000, 30*time.Second, new(1))
	archive := &transitionArchive{lookupErr: errors.New("clickhouse unavailable")}

	findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{stop}, archive)
	require.Error(t, err)
	require.NotErrorIs(t, err, api.ErrProcessNotYetMaterialized,
		"a broken reader is not a materialization race; retrying it would just multiply the failure")
	assert.Empty(t, findings)
}

// TestSensorTamper_DescriptionSurvivesAMissingStopReason: an extension too old to send the reason still produces a
// readable alert rather than one claiming reason zero, which is a real platform value.
func TestSensorTamper_DescriptionSurvivesAMissingStopReason(t *testing.T) {
	t.Parallel()
	stop := transitionEvent("stop-1", "dns_proxy", "stopped", 1_000_000_000_000, 30*time.Second, nil)
	archive := &transitionArchive{events: []api.Event{stop}}

	findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{stop}, archive)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "no reason reported")
	assert.NotContains(t, findings[0].Description, "reason 0")
}

// TestSensorTamper_EvaluatesEveryStopInABatch. Both providers can be switched off together, and #661 is the standing
// reminder that a rule which returns on the first undecided event drops findings the same batch already earned.
func TestSensorTamper_EvaluatesEveryStopInABatch(t *testing.T) {
	t.Parallel()
	const stopNs = int64(1_000_000_000_000)
	decided := transitionEvent("stop-old", "content_filter", "stopped", stopNs, 30*time.Second, new(1))
	undecided := transitionEvent("stop-new", "dns_proxy", "stopped", stopNs, 200*time.Millisecond, new(1))
	archive := &transitionArchive{events: []api.Event{decided, undecided}}

	findings, err := (&SensorTamper{}).Evaluate(context.Background(), []api.Event{undecided, decided}, archive)
	require.ErrorIs(t, err, api.ErrProcessNotYetMaterialized, "the young stop still holds the batch for a retry")
	require.Len(t, findings, 1, "the decided stop's finding must survive the undecided one")
	assert.Equal(t, []string{"stop-old"}, findings[0].EventIDs)
}

// TestSensorTamper_Doc pins the operator-facing surface that the rules API and docs/detection-rules.md render.
func TestSensorTamper_Doc(t *testing.T) {
	t.Parallel()
	r := &SensorTamper{}
	doc := r.Doc()
	assert.Equal(t, []string{"T1562.001"}, r.Techniques())
	assert.Equal(t, []api.Platform{api.PlatformDarwin}, r.Platforms())
	assert.Equal(t, api.SeverityHigh, doc.Severity)
	assert.Equal(t, []string{"sensor_provider_transition"}, doc.EventTypes)
	assert.Equal(t, doc.Title, r.DisplayName())
	assert.NotEmpty(t, doc.Limitations, "the alert reports the stop, not the repair; that has to be stated")
	assert.Empty(t, r.SupportedExclusionMatchTypes())
}

// TestSensorTamper_WindowAndGraceAreOrdered guards the one relationship between the two constants that has to hold: the
// rule must not stop waiting before the window it is measuring has even elapsed, or a recovery inside the window would
// be missed purely because the answer was taken too early.
func TestSensorTamper_WindowAndGraceAreOrdered(t *testing.T) {
	t.Parallel()
	assert.Greater(t, sensorRecoveryGrace, sensorRecoveryWindow,
		"grace %s must exceed window %s", sensorRecoveryGrace, sensorRecoveryWindow)
}
