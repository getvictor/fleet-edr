package api

// Lister enumerates the registered detection rules' metadata. Consumed by rules/internal/operator for GET /api/rules and GET
// /api/attack-coverage. Single-method interface; follows Go's "MethodName + er" naming convention (List -> Lister) per Effective Go.
type Lister interface {
	List() []RuleMetadata
}

// RuleProvider exposes the active set of executable rules. Consumed by detection.Engine at start; hot reload is a future addition.
// "Provider" is the agent-noun form requested by Sonar S8196 for a single-method interface whose method is a plural-noun accessor.
type RuleProvider interface {
	ActiveRules() []Rule
}
