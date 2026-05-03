package catalog

import (
	"context"
	"testing"

	srvbootstrap "github.com/fleetdm/edr/server/bootstrap"
	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/testharness"
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
	db := srvbootstrap.OpenTestDB(t)
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
