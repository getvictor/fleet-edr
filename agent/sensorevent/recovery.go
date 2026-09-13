package sensorevent

import (
	"context"
	"fmt"
)

// RecoveryFailedEventType is the wire event_type emitted when the agent's automatic repair of a stopped capture provider
// runs out of attempts. Registered in schema/events.json; the server does not validate against a closed set, so this needs
// no server change to be accepted and stored.
const RecoveryFailedEventType = "sensor_recovery_failed"

// EmitRecoveryFailed records that automatic recovery gave up on a provider (issue #691).
//
// # Why this is its own event rather than a field on the transition
//
// The package comment explains that transitions carry the story as a PAIR: stopped at T, running at T+36s is a repaired
// tamper. That works because both halves are provider state changes the extension actually reported. This is not one. The
// provider has not transitioned; it is still stopped, and what changed is that the agent stopped trying.
//
// The pair cannot express it either, which is the gap this closes. A stop with no following running transition reads
// identically whether the repair is still in flight, or ran out of attempts minutes ago. Those carry opposite urgency for
// the analyst reading the alert (one may already be fixed, the other is a host that is definitively not capturing), and
// the agent is the only party that knows which, at the only moment it can be known.
//
// # Exactly once per stop episode
//
// The caller is expected to invoke this at the EDGE where the repair budget is spent, not on the level state that follows
// it. The self-heal controller re-asserts its escalation to the health registry on every later liveness report, because
// health is level state that something else keeps overwriting; an event is an append, so the same treatment here would
// produce one event per report for as long as the provider stayed down. selfheal.Options.OnEscalation is the edge-shaped
// seam that exists for this.
// # Why component rides along
//
// The server records this against a health component and closes the record when that component reports healthy again. The
// provider does not name one: it is rendered into the health snapshot from its parent's liveness report and vanishes when the
// parent stops reporting it. The agent holds the parent at this moment, so it states it rather than leaving the server to keep a
// provider-to-component map that would rot silently the first time a provider moved.
//
// Unlike provider and outcome, an empty component does not drop the event. It is additive on a wire an older agent already
// speaks, and the report is still worth having without it: it names a real host that is not capturing, which is the part an
// operator has to act on either way.
func EmitRecoveryFailed(ctx context.Context, emit Emitter, provider, component, outcome string, attempts int) error {
	if emit == nil {
		return nil
	}
	if provider == "" || outcome == "" {
		// A finding that cannot name the provider is not actionable, and the server would have to invent a subject for
		// it. Dropping is better than emitting a record an analyst cannot act on.
		return fmt.Errorf("sensorevent: recovery-failed event needs a provider and an outcome, got %q/%q", provider, outcome)
	}
	payload := map[string]any{
		"provider": provider,
		"outcome":  outcome,
		"attempts": attempts,
	}
	// Omitted rather than sent empty, so the wire carries "not reported" as the absent field the schema describes rather than as
	// a present value the server would have to special-case.
	if component != "" {
		payload["component"] = component
	}
	return emit(ctx, RecoveryFailedEventType, payload)
}
