package api

import "context"

// BatchScope is scratch space the engine creates once per batch and offers to every rule that asks for it, so that rules deriving
// the same thing from the same events derive it once rather than once each.
//
// It is deliberately opaque to the engine. The obvious design, an optional interface handing rules a pre-built adapter, cannot be
// written: detection cannot import server/rules/internal/..., so the adapter type would have to be named here, and the package that
// defines it imports this one for api.Event. That is an import cycle, and it is why the value below is an `any` rather than a type.
// Both the code that stores a derived value and the code that reads it back live inside the rules context, so the assertion is
// between two packages that already know each other and never crosses a context boundary.
//
// A scope lives for exactly one Evaluate call and is discarded with it. Nothing here survives a request, so it is not the
// cross-request state ADR-0010 forbids, and it needs no lock even though the processor evaluates batches concurrently: concurrent
// batches get different scopes.
type BatchScope struct {
	derived map[string]any

	// ancestryIncomplete counts, per rule id, the DISTINCT shells a rule declined because an ancestor they needed had no record,
	// and declinedShells is the dedup set that makes them distinct.
	//
	// Unlike `derived` above, the engine DOES read this, which the opacity note does not forbid: what it cannot do is name a type
	// that lives inside the rules context. A count keyed by a rule id is primitive on both sides, so it crosses the boundary with
	// no adapter and no cycle.
	//
	// It exists because the decline is otherwise invisible (issue #829). A rule that silently reports nothing looks identical to a
	// rule with nothing to report, which is the documented way detections rot unnoticed, so the engine publishes this as a
	// per-attempt span attribute an operator can compare against the rule's alert volume. Not a metric counter: see the engine's
	// note at the annotation for why, and for what the per-attempt framing does and does not let you conclude.
	ancestryIncomplete map[string]int
	declinedShells     map[declinedShell]struct{}
}

// declinedShell identifies one declined shell within a batch, so a rule reached by several trigger events on the same chain counts
// it once. Findings are deduped per shell for the same reason, and the count is specified to be read against the rule's alert
// volume, so counting per trigger event where alerts count per shell would make the two sides of that comparison disagree: several
// temp execs or outbound connections from one unresolved chain would report several declines against at most one lost alert.
type declinedShell struct {
	ruleID   string
	shellPID int
}

// RecordAncestryIncomplete notes that ruleID declined the shell at shellPID because an ancestor it needed was absent from the
// graph. Idempotent per rule and shell within the batch: several trigger events reaching one unresolved chain count once.
//
// Nil-safe for the same reason Derive is: the replay harness and direct callers evaluate rules without a scope, and recording an
// observation must never be the thing that makes them behave differently from the engine.
func (s *BatchScope) RecordAncestryIncomplete(ruleID string, shellPID int) {
	if s == nil {
		return
	}
	if s.declinedShells == nil {
		s.declinedShells = make(map[declinedShell]struct{}, 1)
	}
	key := declinedShell{ruleID: ruleID, shellPID: shellPID}
	if _, dupe := s.declinedShells[key]; dupe {
		return
	}
	s.declinedShells[key] = struct{}{}
	if s.ancestryIncomplete == nil {
		s.ancestryIncomplete = make(map[string]int, 1)
	}
	s.ancestryIncomplete[ruleID]++
}

// AncestryIncompleteCounts returns the per-rule counts recorded during this batch, or nil when nothing was declined. The engine
// reads it once the batch is settled and records it; nothing else should consume it, and it is not a rule-visible signal.
//
// The live map is returned, not a copy. A copy would allocate on a path walked once per rule per batch to guard a mutation no
// caller performs, and the only consumer is the engine's span annotation, which reads one key. Do not write to it.
func (s *BatchScope) AncestryIncompleteCounts() map[string]int {
	if s == nil {
		return nil
	}
	return s.ancestryIncomplete
}

// Derive returns the value stored under key, building it with build the first time this batch asks for it.
//
// The key exists so two unrelated families of rules cannot collide in one slot, which would surface as a wrong-type assertion at
// runtime rather than at compile time. Use a constant owned by the package that also does the type assertion.
//
// A nil scope derives normally and memoizes nothing, so a caller reached outside the engine (a test, the replay harness) does not
// have to construct one to work.
func (s *BatchScope) Derive(key string, build func() any) any {
	if s == nil {
		return build()
	}
	if v, ok := s.derived[key]; ok {
		return v
	}
	v := build()
	if s.derived == nil {
		s.derived = make(map[string]any, 1)
	}
	s.derived[key] = v
	return v
}

// ScopedRule is an OPTIONAL interface a Rule implements when it derives something from a batch that its peers derive too.
//
// Optional and absent from Rule for the same reason NonDetection and AlgorithmNamer are: most rules need nothing from it, and
// requiring it would make every rule carry a parameter it ignores. A rule implementing it is evaluated through EvaluateScoped
// instead of Evaluate, receiving the scope shared with every other scoped rule in the same batch.
//
// An implementation MUST behave identically either way. Evaluate is what the replay harness and direct callers use, and the usual
// shape is for it to call EvaluateScoped with a fresh scope, which is exactly the un-shared behaviour it had before.
type ScopedRule interface {
	Rule

	// EvaluateScoped is Evaluate with access to per-batch scratch space. The scope is never nil when the engine calls it.
	EvaluateScoped(ctx context.Context, scope *BatchScope, events []Event, gr GraphReader) ([]Finding, error)
}
