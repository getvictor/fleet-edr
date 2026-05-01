// Package bootstrap is the dependency-injection entry point for the
// identity context.
//
// New(deps) wires the internal modules (users store, sessions store,
// login handler, middleware, service orchestrator, seeder) and returns
// an *Identity handle whose methods are called from cmd/main and from
// test/integration. ApplySchema runs the DDL for the users + sessions
// tables. RegisterPublicRoutes / RegisterAuthedRoutes hang the HTTP
// surface on a mux. Run starts the background goroutines (today: the
// expired-session cleanup loop).
//
// By convention only server/cmd/* and test/integration/* import this
// package; arch lint enforces it from phase 7.
package bootstrap
