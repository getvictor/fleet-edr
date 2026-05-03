// Package testkit is identity's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full,
// test/integration) reaches for bootstrap. The two contracts are
// deliberately separate: bootstrap is for standing up real wiring;
// testkit is for tests that need just enough of identity to exercise
// some other piece (the users table, a stub User existence check, etc.)
// without spinning up the full Identity service.
//
// Today the package only exposes ApplySchema. As cross-context tests
// grow, this is the right home for identity-specific seeders
// (e.g. SeedUser) and fakes (e.g. UserExistsAlways) so each test file
// stops re-implementing them.
//
// Constraint: this package must NOT import any other bounded context.
// arch-go pins the rule. Cross-context fixture composition is
// server/testdb/full's job, not testkit's.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/bootstrap"
)

// ApplySchema runs identity's DDL + idempotent ALTERs against db.
// Thin wrapper over bootstrap.ApplySchema so the test surface is
// importable separately from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}
