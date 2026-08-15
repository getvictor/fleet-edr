package catalog

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// SensorRecoveryFailed fires when the agent's automatic repair of a stopped capture provider gives up, leaving the host
// not capturing until a human intervenes (T1562.001, issue #691).
//
// # Why this is separate from sensor_tamper rather than folded into it
//
// The two answer different questions and demand different responses. sensor_tamper answers "did somebody switch capture
// off", and is raised five seconds after a stop, when nobody yet knows how the story ends. This answers "is this host
// capturing right now", and is raised only once the answer is settled and negative.
//
// The measured case for splitting them: on the same host, one stop was repaired 35.7 seconds later and the host was fine,
// while another exhausted every attempt and left the host blind. Both produced the identical sensor_tamper alert, word for
// word, because at five seconds the outcomes are indistinguishable. An analyst triaging that alert list could not tell
// which hosts still needed them.
//
// Folding the outcome into sensor_tamper was considered and does not work. Alerts cannot be amended: UpdateAlertStatus is
// the only mutation the store offers and InsertAlert dedups on subject, so there is no path to rewrite the stop alert's
// text once the outcome is known. Waiting for the outcome before raising anything is worse still, because it would delay
// or suppress the case that matters most, a provider that never comes back at all. A second alert is the shape that fits
// what the system can actually do, and it reads correctly on a timeline: capture stopped, then capture could not be
// restored.
//
// # Severity
//
// Critical, one step above the stop it follows. The stop may already have healed by the time anyone looks. This cannot
// have: the agent has stopped trying, and the host stays uncaptured until an operator acts.
//
// # What it does not do
//
// It does not fire on a provider an operator deliberately disabled, and needs no suppression to avoid it. A deliberate
// opt-out is graded extension-side as the provider being ABSENT (issue #649), the self-heal only ever remediates providers
// reported STOPPED, and an event exists here only where a remediation was attempted and exhausted.
type SensorRecoveryFailed struct{}

func (r *SensorRecoveryFailed) ID() string { return "sensor_recovery_failed" }

// SupportedExclusionMatchTypes returns nil for the same reason sensor_tamper does: there is no benign writer to allowlist,
// and the one supported way to run without a provider never reaches this rule.
func (r *SensorRecoveryFailed) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding.
func (r *SensorRecoveryFailed) DisplayName() string { return "EDR sensor could not be restored" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1562.001 (Impair Defenses: Disable or Modify Tools). Same
// technique as the stop it follows, because it reports the same attack having succeeded.
func (r *SensorRecoveryFailed) Techniques() []string { return []string{"T1562.001"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *SensorRecoveryFailed) Doc() api.Documentation {
	return api.Documentation{
		Title: r.DisplayName(),
		Summary: "Flags a stopped capture provider that the agent tried and failed to restore, so the host is not " +
			"capturing until someone intervenes.",
		Description: "The agent repairs a stopped capture provider by itself, and usually succeeds within about half a " +
			"minute. This fires when it does not: every attempt in its budget has been used and the provider is still " +
			"stopped.\n\n" +
			"The practical difference from the sensor-disabled alert is what the host is doing now. That alert is " +
			"raised seconds after capture stops, before anyone can know whether the repair will work, so most of the " +
			"time it describes a host that has already fixed itself. This alert only exists for hosts that have not: " +
			"the telemetry that provider carries is not being collected, and will not be until an operator restores " +
			"it, usually by re-activating the extension on the host.\n\n" +
			"The reported outcome says which kind of failure it was, because they point at different causes. If the " +
			"repair command kept failing, suspect the host application or the system configuration daemon. If every " +
			"repair reported success and the provider stayed stopped, re-enabling is not what the fault needs; that " +
			"shape has been seen when the extension is running but its sessions are wedged.\n\n" +
			"A provider an operator has deliberately turned off never reaches this rule: the agent does not try to " +
			"repair a provider it was told to leave alone.",
		Severity:   api.SeverityCritical,
		EventTypes: []string{sensorRecoveryFailedEventType},
		FalsePositives: []string{
			"None known. The event is only emitted after the agent has attempted and failed a bounded number of repairs, " +
				"so there is no benign path that produces it; a host that reaches this state genuinely is not capturing.",
		},
		Limitations: []string{
			"Reports that automatic recovery gave up, not why the provider stopped in the first place. The stop itself, " +
				"and whether it looked like tampering, is carried by the sensor-disabled alert that precedes it.",
			"An attacker who stops a provider AND prevents the agent from reporting at all produces no event and so no " +
				"alert. That absence is covered by host health going stale, not by this rule.",
		},
	}
}

// sensorRecoveryFailedEventType is the event the agent emits when its repair budget for a provider is spent (issue #691).
// Declared here rather than imported: agent/sensorevent is the producer and the server must not depend on agent packages,
// so the wire contract in schema/events.json is what ties the two together.
const sensorRecoveryFailedEventType = "sensor_recovery_failed"

// Outcomes carried by that event. They are reported verbatim to the analyst rather than collapsed, because they implicate
// different parts of the host.
const (
	outcomeEnableFailed      = "enable_failed"
	outcomeEnableIneffective = "enable_ineffective"
)

// sensorRecoveryFailedPayload is the event's payload. Attempts is carried so the finding can say the repair was genuinely
// tried rather than skipped.
type sensorRecoveryFailedPayload struct {
	Provider string `json:"provider"`
	Outcome  string `json:"outcome"`
	Attempts int    `json:"attempts"`
}

func (r *SensorRecoveryFailed) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

// evalEvent turns one exhausted-repair event into a finding. There is no recovery window and no retry here, unlike sensor_tamper: that
// rule has to wait because a stop's meaning depends on what happens next, whereas this event is already terminal. The agent emits it only
// once its budget is spent, so nothing later can change the answer.
func (r *SensorRecoveryFailed) evalEvent(_ context.Context, evt api.Event, _ api.GraphReader) (*api.Finding, error) {
	if evt.EventType != sensorRecoveryFailedEventType {
		return nil, nil
	}
	var p sensorRecoveryFailedPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, nil
	}
	if p.Provider == "" {
		return nil, nil
	}

	return &api.Finding{
		HostID:   evt.HostID,
		RuleID:   r.ID(),
		Severity: api.SeverityCritical,
		Title:    r.DisplayName(),
		// Process-less, for the same reason the stop is: nothing here identifies who stopped the provider, and naming
		// the extension's own pid would name the victim as the actor.
		Description: sensorRecoveryFailedDescription(p),
		Subject:     sensorRecoveryFailedSubject(p.Provider, evt.EventID),
		EventIDs:    []string{evt.EventID},
	}, nil
}

// sensorRecoveryFailedSubject is the dedup identity. It carries the event's own id so re-processing one exhaustion
// collapses onto a single alert, while a later stop that also exhausts its budget raises its own. Keying on the provider
// alone would let a failure today be silently suppressed by one from last month.
func sensorRecoveryFailedSubject(provider, eventID string) string {
	return providerSubject("sensor_recovery_failed", provider, eventID)
}

func sensorRecoveryFailedDescription(p sensorRecoveryFailedPayload) string {
	diagnosis := "automatic recovery gave up"
	switch p.Outcome {
	case outcomeEnableFailed:
		diagnosis = "every attempt to re-enable it failed"
	case outcomeEnableIneffective:
		diagnosis = "every attempt to re-enable it reported success and it stayed stopped"
	}
	return fmt.Sprintf(
		"EDR capture provider %s is still stopped after %d automatic repair attempts (%s): this host is not reporting "+
			"that telemetry and will not until it is restored by hand (MITRE T1562.001)",
		p.Provider, p.Attempts, diagnosis,
	)
}
