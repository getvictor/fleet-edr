// Package bootstrap is the dependency-injection entry point for the
// endpoint context.
//
// New(deps) wires the internal modules (enrollments mysql store,
// service orchestrator, enroll handler, host-token middleware,
// operator routes) and returns an *Endpoint handle whose methods are
// called from cmd/main and from test/integration. ApplySchema runs
// the DDL for the enrollments table. RegisterPublicRoutes mounts
// POST /api/enroll. RegisterAuthedRoutes mounts the operator-facing
// GET /api/enrollments + POST /api/enrollments/{host_id}/revoke.
// HostTokenMiddleware returns the per-request middleware that gates
// agent endpoints (POST /api/events, GET /api/commands, etc.).
//
// By convention only server/cmd/* and test/integration/* import this
// package; arch lint enforces it from phase 7.
package bootstrap
