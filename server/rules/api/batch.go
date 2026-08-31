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
