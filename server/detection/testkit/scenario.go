package testkit

import (
	"log/slog"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	visibilitytestkit "github.com/fleetdm/edr/server/visibility/testkit"
)

// MemArchive is the in-memory EventArchive for detection tests, aliased from visibility/testkit so detection-internal test packages
// (e.g. mysql_test, internal/tests) reach it through detection's own testkit; the bounded-context import rules do not let them import
// visibility/testkit directly. It satisfies visibilityapi.EventArchive and adds Len for durable-cardinality assertions.
type MemArchive = visibilitytestkit.MemArchive

// NewMemArchive returns an empty in-memory EventArchive for detection tests that seed correlation + evidence reads without a ClickHouse
// container.
func NewMemArchive() *MemArchive { return visibilitytestkit.NewMemArchive() }

// Scenario is a per-test detection-stack fixture: a *mysql.Store wrapping the test DB + an in-memory event archive, and a *graph.Builder
// that materialises events into the processes table. Tests outside detection (e.g. catalog rule tests in server/rules/internal/catalog/)
// use this to seed events + reach api.GraphReader without going through Go's internal-package rule. Post-cutover (ADR-0015) events live
// in the archive, not a MySQL events table, so the fixture seeds the in-memory MemArchive that the store's correlation + evidence reads
// delegate to.
type Scenario struct {
	Store   *mysql.Store
	Builder *graph.Builder
	Archive *visibilitytestkit.MemArchive
}

// NewScenario builds a detection fixture wrapping the given test DB
// (typically returned by server/testdb.Open).
func NewScenario(t *testing.T, db *sqlx.DB) *Scenario {
	t.Helper()
	archive := visibilitytestkit.NewMemArchive()
	s, err := mysql.New(db, archive, nil)
	require.NoError(t, err, "wrap test store")
	return &Scenario{
		Store:   s,
		Builder: graph.NewBuilder(s, slog.Default()),
		Archive: archive,
	}
}
