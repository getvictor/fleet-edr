// Package bootstrap wires the rules bounded context. cmd/* binaries call
// rulesbootstrap.New(deps) once at startup, then ApplySchema, then
// RegisterAuthedRoutes. The returned *Rules handle exposes three
// accessor methods -- PolicyService(), ContentService(), and
// Catalog() -- that return api.PolicyService, api.RuleProvider, and
// api.Lister respectively. The accessor names stay descriptive
// (caller-facing) while the interface names follow Effective Go's
// "method-name + er" convention internally.
//
// ActiveHostsLister and CommandInserter are closure types so cmd/main
// can supply late-bound implementations without rules taking a hard
// dependency on endpoint or response. See phase3.md for the rationale.
package bootstrap
