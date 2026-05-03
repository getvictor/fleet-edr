//go:build integration

// Package tests holds per-context integration tests for the response
// bounded context. Tests skip when EDR_TEST_DSN isn't set, matching
// the project's other DB-using test files (no separate build tag).
// They exercise the full stack via response/bootstrap.New against a
// real MySQL.
//
// Allowed imports for tests in this package:
//   - response/api and response/bootstrap (the context's public surface);
//   - server/store (for the OpenTestStore fixture);
//   - endpoint/api (for WithHostIDForTest, used to fake the
//     host-token middleware on agent-route tests);
//   - other contexts' bootstrap packages (for cross-context end-to-end
//     coverage, e.g. wiring rules.bootstrap with
//     response.Service().Insert as the CommandInserter closure);
//   - platform + standard library + approved third-party.
//
// Other contexts' internal packages are off-limits; the Go compiler
// already enforces this via the internal/ rule.
package tests
