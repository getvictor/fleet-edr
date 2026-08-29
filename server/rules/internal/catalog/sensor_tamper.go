package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fleetdm/edr/server/rules/api"
)

// SensorTamper fires when one of the EDR's own capture providers stops and does not come back within a few seconds
// (T1562.001). Switching off the sensor is the first move in a great many intrusions, and until this rule the product
// detected it nowhere: the sudoers rule covers tampering with the HOST's controls, but nothing watched our own.
//
// The self-heal (issue #632) makes the detection more necessary rather than less. It restores a disabled provider in
// about 35 seconds, and agent health is level state, so once the repair lands the health view reads healthy again and
// the fact that anything happened is gone. The durable transition events (issue #685) are what survive that, and this
// rule is what turns them into something an analyst sees.
//
// # Why a recovery window and not a stop reason
//
// The obvious design is to read the platform's stop reason: `userInitiated` means somebody switched it off, the
// lifecycle reasons mean an upgrade replaced it. That design is wrong, and it was measured wrong rather than argued
// wrong. A routine system-extension cutover on a live host produced `content_filter stopped (reason 1)`, reason 1 being
// `userInitiated`: byte for byte what a deliberate disable produces. A rule keyed on the reason would alert on every
// host on every upgrade, and an alert that fires fleet-wide on a routine upgrade is one operators mute, which is
// exactly how tamper detection fails in practice.
//
// What separates the two is what happens NEXT. Measured on the same host:
//
//	tamper, recovered by the self-heal    37.9s and 32.2s
//	upgrade cutover                        1.1s
//
// A cutover's replacement provider is running about a second later, because the extension is replacing itself. A
// tamper's recovery has to wait out the self-heal's grace window first. So the rule fires on a stop UNLESS a running
// transition for the same provider follows within sensorRecoveryWindow. The 30x separation is what makes the threshold
// safe: it sits an order of magnitude away from both populations, so it is not delicately tuned.
//
// # What this rule does not decide
//
// It reports the stop, not the repair. Whether the provider healed at 35 seconds, stayed down, or exhausted the
// self-heal budget is carried by the subsequent transition events on the host timeline, and none of it is known when
// the alert has to be raised. Gating the alert on the outcome would mean either waiting out the full self-heal (a
// minute of held batches for an alert that may never come) or suppressing the case that matters most, a provider that
// never comes back at all.
//
// A provider an operator deliberately disabled produces no alert and needs no logic here: issue #649 grades a
// deliberate opt-out extension-side and reports the provider ABSENT rather than stopped, and issue #685's recorder
// never emits a transition for an absent provider. The supported configuration is invisible to this rule by
// construction, which is a stronger guarantee than a suppression list.
type SensorTamper struct{}

func (r *SensorTamper) ID() string { return "sensor_tamper" }

// AlgorithmName names the evaluator that decides this rule, for the exported rule file (issue #757). Fires when a provider stop is NOT followed by a matching running transition inside the recovery window.
func (r *SensorTamper) AlgorithmName() string { return "absence_within_window" }

// SupportedExclusionMatchTypes returns nil: this rule consults no exclusions. There is no per-host tuning to offer, because
// there is no benign writer to allowlist. The one supported way to run without a provider is to disable it, which is
// reported as absence and never reaches the rule at all.
func (r *SensorTamper) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding.
func (r *SensorTamper) DisplayName() string { return "EDR sensor disabled" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1562.001 (Impair Defenses: Disable or Modify Tools).
func (r *SensorTamper) Techniques() []string { return []string{"T1562.001"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *SensorTamper) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags one of the EDR's own capture providers stopping without coming back within a few seconds.",
		Description: "Detects tampering with the EDR itself. A capture provider (the content filter or the DNS proxy) " +
			"stopping means the host stops reporting the telemetry that provider carries, so an attacker who can " +
			"switch it off can work unobserved.\n\n" +
			"The agent restores a stopped provider automatically, in about 35 seconds. That repair is why the rule " +
			"exists rather than why it is unnecessary: agent health only reports what is true now, so once the " +
			"provider is back the health view reads healthy and nothing records that it was ever off. The alert is " +
			"the durable account.\n\n" +
			"An agent upgrade also stops providers, as part of replacing the system extension, and the platform " +
			"reports the same stop reason for that as for somebody switching capture off. The rule separates them by " +
			"how fast capture resumes: an upgrade's replacement provider runs about a second later, while a stop that " +
			"needed the automatic repair takes tens of seconds. A provider that resumes within a few seconds is " +
			"therefore not reported.\n\n" +
			"A provider an operator has deliberately turned off (the DNS proxy is optional) is reported as absent " +
			"rather than stopped and never reaches this rule.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{sensorTransitionEventType},
		FalsePositives: []string{
			"An upgrade whose replacement provider takes more than a few seconds to start. The upgrade cutover measured on a " +
				"live host resumed capture in about a second; a host slow enough to exceed the window would also be a host " +
				"that was genuinely not capturing for that long.",
		},
		Limitations: []string{
			"Reports that capture stopped, not whether it was restored. The repair (or its failure) is carried by the " +
				"following transition events on the host's timeline rather than by the alert.",
			"An attacker who stops a provider and prevents the agent from reporting it at all (killing the agent, or " +
				"blocking upload) produces no transition event and so no alert. That absence is covered by host health " +
				"going stale, not by this rule.",
		},
	}
}

// sensorTransitionEventType is the event the agent emits when a capture provider changes state (issue #685). Declared
// here rather than imported: agent/sensorevent is the producer and the server must not depend on agent packages, so the
// wire contract in schema/events.json is what ties the two together.
const sensorTransitionEventType = "sensor_provider_transition"

// Provider states carried by that event. Absence of a provider is a deliberate opt-out and never produces an event, so
// there is no third state to handle here.
const (
	sensorStateRunning = "running"
	sensorStateStopped = "stopped"
)

// sensorRecoveryWindow is how long after a stop a resumed provider still counts as an upgrade cutover rather than a
// tamper. Measured populations are 1.1s (cutover) and 32-38s (tamper recovered by the self-heal), about 30x apart, and 5s
// sits between them: 4.5x above the cutover and 6.4x below the fastest repair. It is deliberately NOT derived from the
// self-heal's grace window, because coupling the two would let a change to the repair timing silently retune the detection.
const sensorRecoveryWindow = 5 * time.Second

// sensorRecoveryGrace is how long the rule waits before concluding that no recovery is coming. It must exceed the window, because a
// recovery at the far edge of the window still has to be uploaded (1s agent interval) and archived before the rule can see it. Inside the
// grace, an unanswered stop raises the retryable sentinel so the processor re-evaluates the batch rather than deciding early; past it, the
// stop is reported. Bounding the wait is what stops a stop whose recovery never arrives from retrying forever.
const sensorRecoveryGrace = 8 * time.Second

// sensorTransitionPayload is the transition event's payload. StopReason is the platform's own reason, carried unreduced; the rule does not
// branch on it (see the type comment) but the alert quotes it, because it is what an analyst compares against the platform's documented
// values.
type sensorTransitionPayload struct {
	Provider   string `json:"provider"`
	State      string `json:"state"`
	StopReason *int   `json:"stop_reason"`
}

func (r *SensorTamper) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

func (r *SensorTamper) evalEvent(ctx context.Context, evt api.Event, s api.GraphReader) (*api.Finding, error) {
	if evt.EventType != sensorTransitionEventType {
		return nil, nil
	}
	var p sensorTransitionPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, nil
	}
	if p.State != sensorStateStopped || p.Provider == "" {
		return nil, nil
	}

	resumed, err := r.resumedWithinWindow(ctx, s, evt, p.Provider)
	if err != nil {
		return nil, err
	}
	if resumed {
		return nil, nil
	}
	if withinGrace(evt.IngestedAtNs, time.Now().UnixNano(), sensorRecoveryGrace) {
		// The window has not fully elapsed (or a recovery inside it has not been archived yet), so "no recovery found"
		// is not yet an answer. Raise the retryable sentinel: the processor nacks and re-evaluates, and alert dedup on
		// the subject makes the re-run idempotent. Past the grace this branch is not taken and the stop is reported,
		// so an unanswered stop cannot hold its batch indefinitely.
		return nil, fmt.Errorf("sensor_tamper %s stop on host %s awaiting recovery window: %w",
			p.Provider, evt.HostID, api.ErrRetryBatch)
	}

	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: sensorTamperDescription(p),
		// Process-less: nothing in the transition event identifies who stopped the provider. The platform reports that
		// a provider stopped, not which process asked for it, and attributing it to the extension's own pid would name
		// the victim as the actor.
		Subject:  sensorTamperSubject(p.Provider, evt.EventID),
		EventIDs: []string{evt.EventID},
	}, nil
}

// resumedWithinWindow reports whether a running transition for the same provider follows the stop inside the recovery
// window. The read is bounded to that window on one host and one event type, which is the archive's sorting-key prefix.
//
// The window is measured on event time, not ingest time: both events are emitted by the same agent on the same host, so
// they share a clock, and the gap between them is precisely what the rule is measuring.
func (r *SensorTamper) resumedWithinWindow(
	ctx context.Context, s api.GraphReader, evt api.Event, provider string,
) (bool, error) {
	tr := api.TimeRange{FromNs: evt.TimestampNs, ToNs: evt.TimestampNs + sensorRecoveryWindow.Nanoseconds()}
	transitions, err := s.GetHostEventsByType(ctx, evt.HostID, sensorTransitionEventType, tr)
	if err != nil {
		return false, fmt.Errorf("sensor_tamper recovery lookup for host %s: %w", evt.HostID, err)
	}
	for _, t := range transitions {
		var tp sensorTransitionPayload
		if err := json.Unmarshal(t.Payload, &tp); err != nil {
			continue
		}
		if tp.Provider == provider && tp.State == sensorStateRunning {
			return true, nil
		}
	}
	return false, nil
}

// sensorTamperSubject is the dedup identity for this process-less alert. It carries the stop's own event id, so re-evaluating the same stop
// (which the retry above does by design) collapses onto one alert, while a genuinely new stop later on raises a new one. Keying on the
// provider alone would mean a tamper today is silently suppressed by an alert from last month.
func sensorTamperSubject(provider, eventID string) string {
	return providerSubject("sensor_stop", provider, eventID)
}

func sensorTamperDescription(p sensorTransitionPayload) string {
	reason := "no reason reported"
	if p.StopReason != nil {
		reason = fmt.Sprintf("platform stop reason %d", *p.StopReason)
	}
	return fmt.Sprintf(
		"EDR capture provider %s stopped (%s) and had not resumed %s later: the host is not reporting this telemetry (MITRE T1562.001)",
		p.Provider, reason, sensorRecoveryWindow,
	)
}
