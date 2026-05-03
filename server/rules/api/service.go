package api

import (
	"context"
	"encoding/json"
)

// PolicyService is the rules-context surface for the active blocklist
// policy. Consumed by:
//   - endpoint/internal/service at enroll time (ActiveCommandPayload),
//   - rules/internal/operator at PUT /api/policy time (Get + Update),
//   - rules/internal/operator at GET /api/policy time (Get).
//
// The interface intentionally exposes BOTH the typed BlocklistPolicy
// (for the operator surface) AND the pre-marshaled command payload
// (for the agent fan-out path). Callers that fan out commands never
// allocate a payload struct per host; the bytes are marshaled once.
type PolicyService interface {
	// Get returns the active default policy. Returns ErrPolicyNotFound
	// when the seed row is missing -- operationally a freshly-broken
	// schema, not a routine state.
	Get(ctx context.Context) (BlocklistPolicy, error)

	// Update mutates the active default policy. Bumps the version
	// atomically inside a transaction. Returns ErrInvalidPath /
	// ErrInvalidHash on validation failures (mapped to 400 by the
	// operator handler).
	Update(ctx context.Context, req UpdateRequest) (BlocklistPolicy, error)

	// ActiveCommandPayload returns the active policy already marshaled
	// as a set_blocklist command payload, plus the policy version (for
	// audit) and a hasContent flag so callers can skip the fan-out
	// when the blocklist is empty (an empty policy is still a valid
	// state -- see admin's "operator panic-button" path -- but
	// pushing it to a freshly-enrolled agent accomplishes nothing).
	ActiveCommandPayload(ctx context.Context) (payload json.RawMessage, version int64, hasContent bool, err error)
}

// Lister enumerates the registered detection rules' metadata.
// Consumed by rules/internal/operator for GET /api/rules and
// GET /api/attack-coverage. Single-method interface; follows Go's
// "MethodName + er" naming convention (List -> Lister) per Effective
// Go.
type Lister interface {
	List() []RuleMetadata
}

// RuleProvider exposes the active set of executable rules. Consumed
// by detection.Engine at start; hot reload is a future addition.
// "Provider" is the agent-noun form requested by Sonar S8196 for a
// single-method interface whose method is a plural-noun accessor.
type RuleProvider interface {
	ActiveRules() []Rule
}
