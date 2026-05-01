// Package integration holds cross-context integration tests that exercise
// scenarios spanning multiple bounded contexts (e.g., enroll a host via
// endpoint, ingest events via detection, see an alert, issue a command via
// response). Tests live behind the //go:build integration tag.
//
// This package may import any context's bootstrap/ and api/ packages. It
// cannot import any context's internal/... because Go's internal/ rule
// blocks the import structurally (test/integration/ lives outside the
// server/<context>/ subtree).
//
// The skeleton in this file becomes a real cross-context fixture helper
// once the second context (phase 2) lands.
package integration
