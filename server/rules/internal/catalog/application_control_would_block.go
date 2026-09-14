package catalog

import (
	"context"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// ApplicationControlWouldBlock is the built-in pass-through rule that turns an `application_control_would_block` ingest event into a
// monitor record. The extension emits that event when the policy allowed an exec that matched a BLOCK rule whose enforcement is DETECT.
//
// It is ApplicationControlBlock's twin: the same payload, gate and subject process, so its findings carry the matched app-control
// rule's id and severity and the matched identifier. What differs is where they land. The rule declares monitor as its default mode,
// so each finding is kept as a monitor record rather than raised as an alert: nothing was blocked, nobody needs notifying, and an
// operator deciding whether to promote the app-control rule to PROTECT reads the records from the rule's monitor-records page.
//
// The subject process is the one that attempted the exec, as for a block: the event is stamped with the AUTH_EXEC instant, before
// the image is replaced. For a would-block the exec then goes ahead, so the binary appears as that process's next generation in the
// tree, and a record for the same rule and process deduplicates exactly as the block alert it would become does.
type ApplicationControlWouldBlock struct{}

// applicationControlWouldBlockEventType is the event_type the extension emits for a DETECT match. Mirrored on the Swift side in
// `extension/edr/extension/ESFSubscriber.swift`.
const applicationControlWouldBlockEventType = "application_control_would_block"

func (r *ApplicationControlWouldBlock) ID() string { return "application_control_would_block" }

// NonDetectionKind declares this a projection, as ApplicationControlBlock does: the host already decided, and this rule renders the
// decision. It keeps the rule off the operator-facing catalog surfaces, which also keeps its mode out of detection tuning.
func (r *ApplicationControlWouldBlock) NonDetectionKind() api.NonDetectionKind {
	return api.NonDetectionProjection
}

// DefaultMode is monitor, which is what makes a DETECT match a monitor record instead of an alert.
func (r *ApplicationControlWouldBlock) DefaultMode() api.DetectionRuleMode {
	return api.DetectionRuleModeMonitor
}

// SupportedExclusionMatchTypes returns nil: this rule consults no exclusions.
func (r *ApplicationControlWouldBlock) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return nil
}

// DisplayName is the catalog entry's name. As with ApplicationControlBlock, a record's title is computed per match rather than taken
// from here.
func (r *ApplicationControlWouldBlock) DisplayName() string { return "Application control would-block" }

// Techniques returns an empty slice, for the reason ApplicationControlBlock gives.
func (r *ApplicationControlWouldBlock) Techniques() []string { return []string{} }

func (r *ApplicationControlWouldBlock) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Keeps every exec a DETECT application-control rule would have blocked as a monitor record.",
		Description: "When an exec matches a BLOCK rule whose enforcement is DETECT, and no PROTECT rule, the extension lets it run and " +
			"emits an `application_control_would_block` event. This built-in rule keeps each one as a monitor record under the " +
			"matched rule's id, with that rule's severity, so an operator can read what the rule matches before promoting it to " +
			"PROTECT. Records deduplicate on the process, like any monitor record.",
		Severity:   api.SeverityMedium,
		EventTypes: []string{applicationControlWouldBlockEventType},
	}
}

// Evaluate maps each accepted would-block event to a Finding, exactly as ApplicationControlBlock.Evaluate does for block events.
func (r *ApplicationControlWouldBlock) Evaluate(ctx context.Context, events []api.Event, gr api.GraphReader) ([]api.Finding, error) {
	return evaluateRuleMatchEvents(ctx, events, gr, ruleMatchRendering{
		eventType:   applicationControlWouldBlockEventType,
		title:       wouldBlockTitle,
		description: wouldBlockDescription,
	})
}

// wouldBlockTitle renders "Application would be blocked: Calculator".
func wouldBlockTitle(p applicationControlBlockPayload) string {
	return titleWithBinaryName("Application would be blocked", p.Path)
}

// wouldBlockDescription names the rule type and the matched identifier. Unlike a block alert it does not use the rule's custom
// message, which is written for the person whose exec is denied and reads as false on a record of an exec that ran.
func wouldBlockDescription(p applicationControlBlockPayload) string {
	return fmt.Sprintf("Allowed by a DETECT %s rule for %s", p.RuleType, p.Identifier)
}
