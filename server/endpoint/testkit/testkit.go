// Package testkit is endpoint's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full,
// test/integration) reaches for bootstrap. The two contracts are
// deliberately separate so per-context unit tests don't couple to
// endpoint's wiring layer.
//
// Today the package only exposes ApplySchema. As cross-context tests
// grow, this is the right home for endpoint-specific seeders
// (e.g. SeedEnrollment, MintHostToken) and fakes so each test file
// stops re-implementing them.
//
// Constraint: this package must NOT import any other bounded context.
// arch-go pins the rule.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/endpoint/bootstrap"
)

// ApplySchema runs endpoint's DDL against db. Thin wrapper over bootstrap.ApplySchema so the test surface is importable separately
// from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
