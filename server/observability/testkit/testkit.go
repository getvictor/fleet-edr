// Package testkit is observability's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full) reaches for bootstrap. The two contracts are deliberately
// separate. Today the package only exposes ApplySchema.
//
// Constraint: this package must NOT import any other bounded context. arch-go pins the rule.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/observability/bootstrap"
)

// ApplySchema runs observability's DDL against db. Thin wrapper over bootstrap.ApplySchema so the test surface is importable
// separately from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
