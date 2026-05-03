//go:build integration

// Package tests holds per-context integration tests for the identity
// context. Tests live behind the //go:build integration tag and exercise
// the full stack via identity/bootstrap.New against a real MySQL.
//
// Imports are restricted to the identity context's public surface
// (identity/api, identity/bootstrap) plus platform packages, so the
// compiler refuses any leak into another context's internals.
package tests
