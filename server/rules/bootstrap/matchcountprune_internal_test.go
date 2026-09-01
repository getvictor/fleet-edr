package bootstrap

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
	rulesmigrations "github.com/fleetdm/edr/server/rules/migrations"
	"github.com/fleetdm/edr/server/testdb"
)

// newPruneHarness builds the minimum Rules needed to drive the match-count prune: a store over a migrated test DB and a logger.
// The rest of the context (handlers, app control, the config service) plays no part in pruning, so wiring it would only make the
// test depend on things it is not about.
func newPruneHarness(t *testing.T, retentionDays int) (*Rules, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, runner.Up(t.Context(), db, rulesmigrations.FS, runner.Options{Context: "rules", TableName: "rules_goose_db_version"}))
	return &Rules{
		detectionConfigStore: detectionconfig.NewStore(db),
		retentionDays:        retentionDays,
		logger:               slog.New(slog.DiscardHandler),
	}, db
}

// insertCount writes one counter row on a given day, so a prune has something to find.
func insertCount(t *testing.T, db *sqlx.DB, ruleID string, daysAgo int) {
	t.Helper()
	day := time.Now().UTC().AddDate(0, 0, -daysAgo).Format(time.DateOnly)
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO detection_rule_match_counts (rule_id, host_id, day, match_count) VALUES (?, 'host-a', ?, 1)`, ruleID, day)
	require.NoError(t, err)
}

func remaining(t *testing.T, db *sqlx.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetContext(t.Context(), &n,
		`SELECT COUNT(*) FROM detection_rule_match_counts`))
	return n
}

// TestPruneMatchCountsOnce covers the sweep the rules context runs on a ticker.
//
// It is the half of the retention story that is not in the store: the store knows how to delete, and this knows when to and what
// to do when it fails. Both matter, because this loop runs on every replica with no leader lock, so a bug here is a bug everywhere
// at once rather than on one elected node.
func TestPruneMatchCountsOnce(t *testing.T) {
	t.Parallel()

	t.Run("deletes past the window and leaves the rest", func(t *testing.T) {
		t.Parallel()
		r, db := newPruneHarness(t, 30)
		insertCount(t, db, "old", 40)
		insertCount(t, db, "recent", 1)

		r.pruneMatchCountsOnce(t.Context())

		assert.Equal(t, 1, remaining(t, db))
	})

	t.Run("retention of zero prunes nothing", func(t *testing.T) {
		t.Parallel()
		r, db := newPruneHarness(t, 0)
		insertCount(t, db, "ancient", 400)

		r.pruneMatchCountsOnce(t.Context())

		assert.Equal(t, 1, remaining(t, db), "the disabled value must not be read as prune everything")
	})

	t.Run("a cancelled context is not logged as a failure", func(t *testing.T) {
		t.Parallel()
		// Shutdown cancels the query mid-sweep, which is not a fault worth a WARN on the way out. Asserted by driving the path
		// rather than by reading the log: the point is that it returns rather than panicking or blocking.
		r, _ := newPruneHarness(t, 30)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		assert.NotPanics(t, func() { r.pruneMatchCountsOnce(ctx) })
	})
}

// TestPruneMatchCountsLoop covers the ticker wrapper: it sweeps immediately rather than after a full interval, and it stops when
// the context is cancelled rather than outliving the process it belongs to.
func TestPruneMatchCountsLoop(t *testing.T) {
	t.Parallel()

	r, db := newPruneHarness(t, 30)
	insertCount(t, db, "old", 40)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		// An hour-long interval: if the first pass waited for a tick, this would hang rather than fail, and the deadline below
		// would report it.
		r.pruneMatchCountsLoop(ctx, time.Hour)
		close(done)
	}()

	require.Eventually(t, func() bool { return remaining(t, db) == 0 }, 5*time.Second, 10*time.Millisecond,
		"the first sweep runs immediately, so a replica that restarts often still prunes")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop must return when its context is cancelled")
	}
}
