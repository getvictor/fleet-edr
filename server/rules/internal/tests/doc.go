// Package tests holds per-context integration tests for the rules
// context. Tests skip when EDR_TEST_DSN isn't set, matching the
// project's other DB-using test files (no separate build tag). They
// exercise the full stack via rules/bootstrap.New against a real MySQL.
//
// Imports are restricted to the rules context's public surface
// (rules/api, rules/bootstrap) plus platform packages and (for fan-out
// tests) endpoint/bootstrap to enroll real hosts. The compiler refuses
// any leak into another context's internals.
package tests
