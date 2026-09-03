// Package testkit is rulecontent's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, cmd/fleet-edr-migrate, server/testdb/full, test/integration) reaches for
// bootstrap. Same split every other context uses.
//
// Constraint: this package must NOT import another bounded context. arch-go pins the rule, and cross-context fixture composition
// is server/testdb/full's job.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rulecontent/bootstrap"
)

// ApplySchema runs rulecontent's DDL against db. Thin wrapper over bootstrap.ApplySchema so the test surface is importable
// separately from the production wiring surface.
//
// Registered in server/testdb/full's applySchemas, which is what makes full.Open's promise of "every context's schema" true for
// this context. Without it, every test needing the corpus tables hand-applies the schema, which is both noise and a claim that
// quietly stops holding the moment someone believes the fixture.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
