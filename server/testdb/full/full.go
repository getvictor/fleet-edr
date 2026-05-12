// Package full opens an isolated test database with every bounded
// context's authoritative schema applied. This is the canonical
// fixture for cross-context integration tests; use it from
// `*/internal/tests/`, `test/integration/`, or anywhere else outside
// a single context's internal/ tree.
//
// Per-context unit tests inside `*/internal/X/` should use
// server/testdb (the lightweight Open) plus their own context's
// testkit.ApplySchema, to avoid the cycle
// X → testdb/full → ctx/bootstrap → X.
//
// Schemas are applied in dependency order: identity first (owns
// users + sessions), then endpoint, rules, response, detection. With
// no cross-context FKs in the current schema the remaining four are
// independent; the order is preserved for readability and so future
// cross-context FKs (e.g. an audit log keyed by user_id) Just Work
// without re-shuffling the call sites.
//
// full imports each context's testkit rather than its bootstrap so
// the rule "production wiring (bootstrap) and test fixtures (testkit)
// are separate contracts" stays clean: cmd/main calls bootstrap, every
// test surface goes through testkit.
package full

import (
	"testing"

	"github.com/jmoiron/sqlx"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	endpointtestkit "github.com/fleetdm/edr/server/endpoint/testkit"
	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	responsetestkit "github.com/fleetdm/edr/server/response/testkit"
	rulestestkit "github.com/fleetdm/edr/server/rules/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// Open creates an isolated test database (via testdb.Open) and
// applies every bounded context's schema against it.
func Open(t *testing.T) *sqlx.DB {
	t.Helper()
	db := testdb.Open(t)
	ctx := t.Context()

	if err := identitytestkit.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply identity schema: %v", err)
	}
	if err := endpointtestkit.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply endpoint schema: %v", err)
	}
	if err := rulestestkit.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply rules schema: %v", err)
	}
	if err := responsetestkit.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply response schema: %v", err)
	}
	if err := detectiontestkit.ApplySchema(ctx, db); err != nil {
		t.Fatalf("apply detection schema: %v", err)
	}
	return db
}
