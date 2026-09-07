package catalog

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// SensorRecoveryFailed fires when the agent's automatic repair of a stopped capture provider gives up, leaving the host
// not capturing until a human intervenes (issue #691). It claims no ATT&CK technique; see Techniques below for why.
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

// NonDetectionKind declares this a health signal, not a detection, so it stays off the operator-facing catalog surfaces
// (GET /api/rules, GET /api/attack-coverage, docs/detection-rules.md). Nothing about registration, evaluation or alert
// persistence changes. Its subject is our own agent: the repair of a stopped capture provider giving up. Both failure shapes it
// reports point at our software (the host application or the system configuration daemon failing the repair, or the extension
// running with wedged sessions), so it establishes nothing about an adversary. A person still has to act on it, which is why it
// keeps its severity; where that signal belongs is being moved to a host-health surface separately.
func (r *SensorRecoveryFailed) NonDetectionKind() api.NonDetectionKind { return api.NonDetectionHealth }

// SupportedExclusionMatchTypes returns nil for the same reason sensor_tamper does: there is no benign writer to allowlist,
// and the one supported way to run without a provider never reaches this rule.
func (r *SensorRecoveryFailed) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding.
func (r *SensorRecoveryFailed) DisplayName() string { return "EDR sensor could not be restored" }

// Techniques returns no MITRE ATT&CK IDs, and the absence is the mapping rather than an omission (issue #754).
//
// It used to claim T1562.001 (Impair Defenses: Disable or Modify Tools) on the grounds that it reported "the same attack having
// succeeded". The rule contradicted itself: its own Limitations say it reports that recovery gave up and NOT why the provider
// stopped, and its Description sends an analyst to look at the host application and the system configuration daemon, which are
// ours. Both outcome values, enable_failed and enable_ineffective, describe this product's repair mechanism failing rather than
// anyone acting against it.
//
// The observed base rate settles it. The 37.8-hour providerless episode on 2026-07-17 was the enable_ineffective shape, and its
// cause was a Settings disable-then-enable leaving the network extension with no filter or DNS sessions: an OS-interaction bug.
// That is the common cause of this alert in practice.
//
// Where the claim actually landed is worth stating, because the obvious answer is no longer the right one. Issue #754 was filed
// about the ATT&CK coverage export, and this rule has since been classified a health signal, which already keeps it off that
// export and off GET /api/rules and the generated reference. What the claim still reached is every ALERT this rule raises: the
// finding declares no techniques of its own, so alert persistence falls back to this list and stamped T1562.001 onto the row an
// analyst reads. That is the surface the removal fixes.
//
// The alert keeps its Critical severity and its operational explanation. Removing an attribution is not a downgrade: without an
// adversary attached this is a visibility and health statement, and that needs no adversary label to earn its severity, since a
// host that is not capturing needs an operator either way. What the removal does take out of the text is the attribution itself,
// which the description used to carry as a trailing "(MITRE T1562.001)" and which is the same claim by another route. Whether
// this belongs on a health surface rather than in the detection feed is a larger question, tracked separately.
//
// Empty and not nil, which is what the interface asks for (see api.Rule) and what the other unmapped rule returns.
func (r *SensorRecoveryFailed) Techniques() []string { return []string{} }

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
	// No technique in the prose either, and review was right that removing it from the structured list alone was half a fix: the
	// description is copied verbatim onto the alert, so an analyst went on reading "(MITRE T1562.001)" on a condition this rule
	// cannot attribute to anyone (issue #754). The operational sentence is what was worth keeping and is untouched.
	return fmt.Sprintf(
		"EDR capture provider %s is still stopped after %d automatic repair attempts (%s): this host is not reporting "+
			"that telemetry and will not until it is restored by hand",
		p.Provider, p.Attempts, diagnosis,
	)
}
