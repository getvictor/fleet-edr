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
// users + sessions), then endpoint, rules, response, detection, and
// observability. With no cross-context FKs in the current schema the
// remaining contexts are independent; the order is preserved for
// readability and so future cross-context FKs (e.g. an audit log keyed
// by user_id) Just Work without re-shuffling the call sites.
//
// full imports each context's testkit rather than its bootstrap so
// the rule "production wiring (bootstrap) and test fixtures (testkit)
// are separate contracts" stays clean: cmd/main calls bootstrap, every
// test surface goes through testkit.
package full

import (
	"context"
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	endpointtestkit "github.com/fleetdm/edr/server/endpoint/testkit"
	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	observabilitytestkit "github.com/fleetdm/edr/server/observability/testkit"
	responsetestkit "github.com/fleetdm/edr/server/response/testkit"
	rulestestkit "github.com/fleetdm/edr/server/rules/testkit"
	"github.com/fleetdm/edr/server/testdb"
	visibilitytestkit "github.com/fleetdm/edr/server/visibility/testkit"
)

// Open creates an isolated test database with every bounded context's schema applied.
//
// The schema is built by running the migrations once per process and replayed as plain DDL for every test after that; see
// testdb.OpenTemplated for why, and for what that preserves. Callers see no difference beyond the fixture being about 2.7x
// cheaper, which matters because the heaviest package calls this 109 times.
//
// Takes testing.TB rather than *testing.T so a benchmark can measure the fixture it depends on. Optimising something that
// cannot be measured is how a "faster" fixture quietly stops being faster.
func Open(tb testing.TB) *sqlx.DB {
	tb.Helper()
	return testdb.OpenTemplated(tb, "full", applySchemas)
}

// applySchemas applies every context's schema in dependency order. Called once per process by OpenTemplated; the ordering
// comment on the package doc explains why identity leads.
func applySchemas(ctx context.Context, db *sqlx.DB) error {
	for _, step := range []struct {
		name  string
		apply func(context.Context, *sqlx.DB) error
	}{
		{"identity", identitytestkit.ApplySchema},
		{"endpoint", endpointtestkit.ApplySchema},
		{"rules", rulestestkit.ApplySchema},
		{"response", responsetestkit.ApplySchema},
		{"detection", detectiontestkit.ApplySchema},
		{"observability", observabilitytestkit.ApplySchema},
		{"visibility", visibilitytestkit.ApplySchema},
	} {
		if err := step.apply(ctx, db); err != nil {
			return fmt.Errorf("apply %s schema: %w", step.name, err)
		}
	}
	return nil
}
