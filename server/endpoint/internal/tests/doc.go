//go:build integration

// Package tests holds per-context integration tests for the endpoint
// context. Tests skip when EDR_TEST_DSN isn't set (matching the
// project's other DB-using test files). They
// exercise the full stack via endpoint/bootstrap.New against a real
// MySQL.
//
// Imports are restricted to the endpoint context's public surface
// (endpoint/api, endpoint/bootstrap) plus platform packages. The
// compiler refuses any leak into another context's internals.
package tests
