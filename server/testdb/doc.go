// Package testdb opens an isolated MySQL test database and applies
// every bounded context's authoritative schema against it.
//
// Bounded contexts are a code-organization construct, not a storage
// one: identity, endpoint, rules, response, and detection share one
// MySQL database. testdb composes each context's package-level
// ApplySchema (and detection's MigrateSchema) so any cross-context
// integration test gets every table it needs from a single fixture.
//
// This package is test-only and arch-go denies non-test packages from
// importing it. Production wiring goes through cmd/main, which calls
// each context's bootstrap.New and then ApplySchema in dependency
// order.
//
// Replaces server/bootstrap/testdb.go, which duplicated CREATE TABLE
// strings as Go literals. Each context now stays the source of truth
// for its own schema.
package testdb
