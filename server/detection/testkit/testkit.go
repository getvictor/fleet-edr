// Package testkit is detection's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full,
// test/integration) reaches for bootstrap. The two contracts are
// deliberately separate so cross-context tests (e.g. rule catalog
// tests living in server/rules/internal/catalog/) don't couple to
// detection's wiring layer.
//
// Three things live here today:
//
//  1. ApplySchema — thin wrapper over bootstrap.ApplySchema so tests
//     get the same DDL production gets.
//  2. Scenario — a per-test fixture that pairs detection's *mysql.Store
//     and *graph.Builder so callers can insert events and materialise
//     the process graph the rule under test will read.
//  3. Replay — fixture-driven rule-test runner: caller points at a dir
//     of <case>.json files, each becomes a sub-test asserting the
//     rule's findings match expected_findings.
//
// Replaces an earlier server/detection/testharness/ package; the
// rename also means cross-context tests import a single
// **.detection.testkit allow-list entry instead of the two
// **.detection.bootstrap + **.detection.testharness entries that an
// interim revision carried as transitional exceptions.
//
// Constraint: testkit may import detection's own internals (it lives
// inside detection/) but must NOT import any other bounded context.
// arch-go pins the rule.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/detection/bootstrap"
)

// ApplySchema runs detection's CREATE TABLE statements against db. Thin wrapper over bootstrap.ApplySchema so the test surface is
// importable separately from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
