package catalog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	"github.com/fleetdm/edr/server/detection/testharness"
	"github.com/fleetdm/edr/server/testdb"
)

// catalogStore is a thin wrapper that exposes the limited
// per-rule-test surface (insert events, materialise the process
// graph, satisfy GraphReader). It hides the *mysql.Store +
// *graph.Builder behind the testharness.Scenario type because
// catalog tests cannot import detection/internal/* directly.
type catalogStore struct {
	scenario *testharness.Scenario
}

func openCatalogStore(t *testing.T) *catalogStore {
	t.Helper()
	db := testdb.Open(t)
	ctx := t.Context()
	require.NoError(t, detectionbootstrap.ApplySchema(ctx, db))
	require.NoError(t, detectionbootstrap.MigrateSchema(ctx, db))
	return &catalogStore{scenario: testharness.NewScenario(t, db)}
}

// InsertEvents inserts a batch into the test DB.
func (c *catalogStore) InsertEvents(ctx context.Context, events []detectionapi.Event) error {
	return c.scenario.Store.InsertEvents(ctx, events)
}

// ProcessBatch runs the graph builder against the events so the rule
// under test sees a populated process graph.
func (c *catalogStore) ProcessBatch(ctx context.Context, events []detectionapi.Event) error {
	return c.scenario.Builder.ProcessBatch(ctx, events)
}

// GraphReader returns the api.GraphReader that rule.Evaluate
// consumes.
func (c *catalogStore) GraphReader() detectionapi.GraphReader {
	return c.scenario.Store
}
