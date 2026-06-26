// Package testkit is visibility's coordinated test-fixture surface. Tests reach for testkit; production wiring (cmd/main) reaches for
// bootstrap. arch-go pins the split and pins testkit to its own context so it cannot become a transitive cross-context sneak-in path.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/visibility/bootstrap"
)

// ApplySchema runs visibility's DDL against db. Thin wrapper over bootstrap.ApplySchema so the test surface is importable separately
// from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
