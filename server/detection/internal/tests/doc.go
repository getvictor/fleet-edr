// Package tests holds per-context integration tests for the detection
// bounded context. Tests skip when EDR_TEST_DSN isn't set, matching
// the project's other DB-using test files. They exercise the full
// stack via detection/bootstrap.New against a real MySQL.
//
// Allowed imports for tests in this package:
//   - detection/api and detection/bootstrap (the context's public surface);
//   - server/bootstrap (for OpenTestDB + the identity-schema preamble);
//   - endpoint/api (for WithHostIDForTest, used to fake the
//     host-token middleware on agent-route tests);
//   - identity/api (for UserExists test fakes);
//   - rules/api (for the rule-set the engine consumes);
//   - other contexts' bootstrap packages (for cross-context end-to-end
//     coverage);
//   - platform + standard library + approved third-party.
package tests
