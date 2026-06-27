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
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
	visibilitytestkit "github.com/fleetdm/edr/server/visibility/testkit"
)

// NewMemArchive returns an in-memory EventArchive for detection tests that seed correlation + evidence reads without a ClickHouse
// container. Re-exported through detection's own testkit so detection-internal test packages (e.g. mysql_test) reach it without
// importing visibility/testkit directly, which the bounded-context import rules do not permit them.
func NewMemArchive() visibilityapi.EventArchive { return visibilitytestkit.NewMemArchive() }

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
	s, err := mysql.New(db, archive)
	require.NoError(t, err, "wrap test store")
	return &Scenario{
		Store:   s,
		Builder: graph.NewBuilder(s, slog.Default()),
		Archive: archive,
	}
}

// SeedAndMaterialise stores the events in the archive (so the rule's correlation + evidence reads find them) and runs ProcessBatch so the
// rule under test sees a populated process graph. Returns the GraphReader the rule's Evaluate consumes.
func (s *Scenario) SeedAndMaterialise(t *testing.T, ctx context.Context, events []detectionapi.Event) detectionapi.GraphReader {
	t.Helper()
	require.NoError(t, s.Archive.Insert(ctx, events), "seed archive")
	require.NoError(t, s.Builder.ProcessBatch(ctx, events), "materialise")
	return s.Store
}

// GraphReader returns the underlying store as a GraphReader
// (rule.Evaluate's third argument).
func (s *Scenario) GraphReader() detectionapi.GraphReader { return s.Store }
