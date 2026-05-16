package catalog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// catalogStore is a thin wrapper that exposes the limited per-rule-test surface (insert events, materialise the process graph,
// satisfy GraphReader). It hides the *mysql.Store + *graph.Builder behind the testkit.Scenario type because catalog tests cannot
// import detection/internal/* directly.
type catalogStore struct {
	scenario *detectiontestkit.Scenario
}

func openCatalogStore(t *testing.T) *catalogStore {
	t.Helper()
	db := testdb.Open(t)
	ctx := t.Context()
	require.NoError(t, detectiontestkit.ApplySchema(ctx, db))
	return &catalogStore{scenario: detectiontestkit.NewScenario(t, db)}
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
