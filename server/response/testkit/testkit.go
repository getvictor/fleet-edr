// Package testkit is response's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full,
// test/integration) reaches for bootstrap. The two contracts are
// deliberately separate.
//
// Today the package only exposes ApplySchema. As cross-context tests
// grow, this is the right home for response-specific seeders (e.g.
// SeedCommand) and fakes (e.g. NoopHeartbeat) so each test file stops
// re-implementing them.
//
// Constraint: this package must NOT import any other bounded context.
// arch-go pins the rule.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/response/bootstrap"
)

// ApplySchema runs response's DDL against db. Thin wrapper over
// bootstrap.ApplySchema so the test surface is importable separately
// from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
