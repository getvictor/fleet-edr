package testkit

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// Scenario is a per-test detection-stack fixture: a *mysql.Store
// wrapping the test DB, and a *graph.Builder that materialises events
// into the processes table. Tests outside detection (e.g. catalog rule
// tests in server/rules/internal/catalog/) use this to seed events +
// reach api.GraphReader without going through Go's internal-package
// rule.
type Scenario struct {
	Store   *mysql.Store
	Builder *graph.Builder
}

// NewScenario builds a detection fixture wrapping the given test DB
// (typically returned by server/testdb.Open).
func NewScenario(t *testing.T, db *sqlx.DB) *Scenario {
	t.Helper()
	s, err := mysql.New(db)
	require.NoError(t, err, "wrap test store")
	return &Scenario{
		Store:   s,
		Builder: graph.NewBuilder(s, slog.Default()),
	}
}

// SeedAndMaterialise inserts the events into the test DB and runs
// ProcessBatch so the rule under test sees a populated process
// graph. Returns the GraphReader the rule's Evaluate consumes.
func (s *Scenario) SeedAndMaterialise(t *testing.T, ctx context.Context, events []detectionapi.Event) detectionapi.GraphReader {
	t.Helper()
	require.NoError(t, s.Store.InsertEvents(ctx, events), "insert events")
	require.NoError(t, s.Builder.ProcessBatch(ctx, events), "materialise")
	return s.Store
}

// GraphReader returns the underlying store as a GraphReader
// (rule.Evaluate's third argument).
func (s *Scenario) GraphReader() detectionapi.GraphReader { return s.Store }
