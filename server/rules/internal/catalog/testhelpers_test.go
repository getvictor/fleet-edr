package catalog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
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

// fakeExclusions is an in-memory api.ExclusionResolver for catalog rule tests. It honours the real per-type match semantics
// (api.MatchExclusionValue) so glob/exact/substring behaviour is exercised, ignores hostID (tests are single-host), and treats an
// empty entry ruleID as shared across rules. Pointer receiver so a test can assert identity (resolver threading).
type fakeExclusions struct {
	entries []fakeExcl
}

type fakeExcl struct {
	ruleID    string
	matchType api.ExclusionMatchType
	value     string
}

func (f *fakeExclusions) Excluded(ruleID string, matchType api.ExclusionMatchType, value, _ string) bool {
	for _, e := range f.entries {
		if (e.ruleID == "" || e.ruleID == ruleID) && e.matchType == matchType && api.MatchExclusionValue(matchType, e.value, value) {
			return true
		}
	}
	return false
}
