// Package tests holds per-context integration tests for the response
// bounded context. Tests skip when EDR_TEST_DSN isn't set, matching
// the project's other DB-using test files (no separate build tag).
// They exercise the full stack via response/bootstrap.New against a
// real MySQL.
//
// Imports are restricted to the response context's public surface
// (response/api, response/bootstrap) plus platform packages and
// other contexts' bootstrap (for cross-context end-to-end coverage,
// e.g. wiring rules.bootstrap with response.Service().Insert as
// CommandInserter).
package tests
