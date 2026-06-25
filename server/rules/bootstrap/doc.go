// Package bootstrap wires the rules bounded context. cmd/* binaries call
// rulesbootstrap.New(deps) once at startup, then ApplySchema, then
// RegisterAuthedRoutes. The returned *Rules handle exposes three
// accessor methods (ContentService(), Catalog(), and
// ApplicationControlStore()) that return api.RuleProvider, api.Lister,
// and api.ApplicationControlStore respectively. The accessor names stay
// descriptive (caller-facing) while the interface names follow Effective
// Go's "method-name + er" convention internally.
//
// HostLister and CommandBatchInserter are closure types Deps takes so cmd/main
// can supply late-bound implementations of the app-control fan-out without
// rules taking a hard dependency on detection or response.
package bootstrap
