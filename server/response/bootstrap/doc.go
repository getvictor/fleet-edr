// Package bootstrap wires the response bounded context. cmd/* binaries
// call responsebootstrap.New(deps) once at startup, then ApplySchema,
// then RegisterAgentRoutes / RegisterAuthedRoutes. The returned
// *Response handle exposes Service for cross-context callers
// (endpoint enroll fan-out, rules policy fan-out, metrics adapter).
//
// Heartbeat is a closure type so cmd/main can supply
// store.UpdateHostLastSeen today and switch to
// detection.api.RecordHostSeen in phase 5 without changing the
// response surface.
package bootstrap
