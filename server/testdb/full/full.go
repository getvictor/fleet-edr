// Package full opens an isolated test database with every bounded
// context's authoritative schema applied. This is the canonical
// fixture for cross-context integration tests; use it from
// `*/internal/tests/`, `test/integration/`, or anywhere else outside
// a single context's internal/ tree.
//
// Per-context unit tests inside `*/internal/X/` should use
// server/testdb (the lightweight Open) plus the relevant context's
// own ApplySchema directly, to avoid an import cycle of
// X → testdb/full → ctx/bootstrap → X.
//
// Schemas are applied in dependency order: identity first (owns
// users + sessions), then endpoint, rules, response, detection. After
// phase 5 dropped the cross-context fk_alerts_updated_by FK the
// remaining four are independent; the order is preserved for
// readability.
package full

import (
	"testing"

	"github.com/jmoiron/sqlx"

	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	responsebootstrap "github.com/fleetdm/edr/server/response/bootstrap"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb"
)

// Open creates an isolated test database (via testdb.Open) and
// applies every bounded context's schema against it.
func Open(t *testing.T) *sqlx.DB {
	t.Helper()
	db := testdb.Open(t)
	ctx := t.Context()

	if err := identitybootstrap.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply identity schema: %v", err)
	}
	if err := endpointbootstrap.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply endpoint schema: %v", err)
	}
	if err := rulesbootstrap.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply rules schema: %v", err)
	}
	if err := responsebootstrap.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply response schema: %v", err)
	}
	if err := detectionbootstrap.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply detection schema: %v", err)
	}
	if err := detectionbootstrap.MigrateSchema(ctx, db); err != nil {
		t.Fatalf("apply detection migrations: %v", err)
	}
	return db
}
