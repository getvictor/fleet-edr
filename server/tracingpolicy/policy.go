// Package tracingpolicy holds the EDR route-to-sampling-tier policy: the mapping from HTTP routes to the tiers defined in
// internal/observability/tracing. It is the "policy" half of the mechanism/policy split (the sampler + registry are the mechanism).
// Keeping it in the server layer lets the shared tracing package stay free of EDR routes, and lets both server binaries
// (fleet-edr-server and fleet-edr-ingest) share one classification.
//
// Classification keys are "METHOD /path" matching the span name the HTTP span-name formatter emits. Because that span name is the raw
// request path (otelhttp runs before net/http route matching), only routes whose template has NO path parameters can be classified
// here; the agent data-plane routes that drive volume are all parameter-free, so they match exactly. Parameter-bearing routes
// (e.g. GET /api/alerts/{id}) are operator detail reads at low volume and intentionally fall to TierFull (100%), the safe default.
package tracingpolicy

import "github.com/fleetdm/edr/internal/observability/tracing"

type route struct {
	method string
	path   string
}

// highVolume is the agent data plane: it dominates request volume and is downsampled hardest. GET /api/commands is the agent's
// command poll (the operator detail read GET /api/commands/{id} carries a path param and is not classified here, so it stays Full).
var highVolume = []route{
	{"POST", "/api/events"},
	{"GET", "/api/commands"},
	{"POST", "/api/token/refresh"},
	{"POST", "/api/enroll"},
}

// standard is operator/UI read traffic: the parameter-free dashboard and settings GET endpoints. Sampled at the standard ratio.
var standard = []route{
	{"GET", "/api/session"},
	{"GET", "/api/audit-events"},
	{"GET", "/api/hosts"},
	{"GET", "/api/alerts"},
	{"GET", "/api/rules"},
	{"GET", "/api/attack-coverage"},
	{"GET", "/api/enrollments"},
	{"GET", "/api/settings/sso"},
	{"GET", "/api/settings/users"},
	{"GET", "/api/settings/service-accounts"},
	{"GET", "/api/settings/tracing"},
}

// drop is liveness/health probe traffic: high volume, zero diagnostic value. Dropped unconditionally (even under force_full).
var drop = []route{
	{"GET", "/livez"},
	{"GET", "/readyz"},
	{"GET", "/health"},
}

// Register applies the EDR sampling-tier policy to reg. Safe to call with routes a given binary does not serve: an unused registry
// entry is inert. Routes absent from every list fall to TierFull via Registry.Lookup's zero value.
func Register(reg *tracing.Registry) {
	for _, r := range highVolume {
		reg.Register(r.method, r.path, tracing.TierHighVolume)
	}
	for _, r := range standard {
		reg.Register(r.method, r.path, tracing.TierStandard)
	}
	for _, r := range drop {
		reg.Register(r.method, r.path, tracing.TierDrop)
	}
}
