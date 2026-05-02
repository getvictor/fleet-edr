// Package bootstrap wires the rules bounded context. cmd/* binaries call
// rulesbootstrap.New(deps) once at startup, then ApplySchema, then
// RegisterAuthedRoutes. The returned *Rules handle exposes
// PolicyService, RuleProvider, and Lister for cross-context callers.
//
// ActiveHostsLister and CommandInserter are closure types so cmd/main
// can supply late-bound implementations without rules taking a hard
// dependency on endpoint or response. See phase3.md for the rationale.
package bootstrap
