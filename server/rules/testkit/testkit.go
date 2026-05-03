// Package testkit is rules' coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full,
// test/integration) reaches for bootstrap. The two contracts are
// deliberately separate.
//
// Today the package only exposes ApplySchema. As cross-context tests
// grow, this is the right home for rules-specific seeders (e.g.
// SeedPolicy) and fakes so each test file stops re-implementing them.
//
// Constraint: this package must NOT import any other bounded context.
// arch-go pins the rule.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/bootstrap"
)

// ApplySchema runs rules' DDL + seed-row inserts against db. Thin
// wrapper over bootstrap.ApplySchema so the test surface is importable
// separately from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
