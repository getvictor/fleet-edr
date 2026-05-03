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
// Only server/cmd/*, server/testdb/full, and test/integration/* import
// this package; arch-go enforces the rule (see arch-go.yml).
package bootstrap
