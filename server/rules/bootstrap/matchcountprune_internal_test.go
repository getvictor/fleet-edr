package bootstrap

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
	"github.com/fleetdm/edr/server/rules/internal/operator"
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
	store := detectionconfig.NewStore(db)
	return &Rules{
		detectionConfigStore: store,
		// Run fans out to the config refresh as well as the prune, so it needs a real service; the prune tests below do not touch
		// it, and a nil one would turn a Run lifecycle test into a nil dereference rather than a test.
		detectionConfigSvc: detectionconfig.NewService(store, nil, nil, slog.New(slog.DiscardHandler)),
		retentionDays:      retentionDays,
		logger:             slog.New(slog.DiscardHandler),
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

		r.pruneCountersOnce(t.Context())

		assert.Equal(t, 1, remaining(t, db))
	})

	t.Run("retention of zero prunes nothing", func(t *testing.T) {
		t.Parallel()
		r, db := newPruneHarness(t, 0)
		insertCount(t, db, "ancient", 400)

		r.pruneCountersOnce(t.Context())

		assert.Equal(t, 1, remaining(t, db), "the disabled value must not be read as prune everything")
	})

	t.Run("a cancelled context is not logged as a failure", func(t *testing.T) {
		t.Parallel()
		// Shutdown cancels the query mid-sweep, which is not a fault worth a WARN on the way out. Asserted by driving the path
		// rather than by reading the log: the point is that it returns rather than panicking or blocking.
		r, _ := newPruneHarness(t, 30)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		assert.NotPanics(t, func() { r.pruneCountersOnce(ctx) })
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
		r.pruneCountersLoop(ctx, time.Hour)
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

// TestRun_DrivesTheMatchCountPrune covers the production entry point rather than the loop beneath it.
//
// Every other test here calls pruneMatchCountsLoop directly, which means deleting its call from Run would disable pruning in
// production and leave the whole suite green. That is the failure this exists to catch: the loop is well covered and the line that
// starts it was not covered at all.
//
// It also pins that Run RETURNS on cancellation. Run fans out to two goroutines under a WaitGroup, so a fan-out that forgets to
// wait, or a loop that ignores its context, hangs shutdown rather than failing anything.
func TestRun_DrivesTheMatchCountPrune(t *testing.T) {
	t.Parallel()

	r, db := newPruneHarness(t, 30)
	insertCount(t, db, "old", 40)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return remaining(t, db) == 0 }, 5*time.Second, 10*time.Millisecond,
		"Run must actually start the prune, not merely be able to")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run must return once its context is cancelled, or shutdown hangs on it")
	}
}

// TestMonitorMatchRecorder_IsTheStore covers the other end of the same wiring hop.
//
// cmd/main joins these two accessors: rulesCtx.MonitorMatchRecorder() into detectionCtx.SetMonitorMatchRecorder(). The Runner test
// in the pipeline package covers the detection side; this covers the rules side, so a nil returned here cannot silently disable
// the durable counter while every other test passes.
func TestMonitorMatchRecorder_IsTheStore(t *testing.T) {
	t.Parallel()

	r, _ := newPruneHarness(t, 30)

	rec := r.MonitorMatchRecorder()
	require.NotNil(t, rec, "a nil recorder would leave production emitting metrics and persisting nothing")
	assert.Same(t, r.detectionConfigStore, rec)
}

// allowAllAuthZ lets the wiring test reach the handler; the endpoint's own authz gating is covered in the operator package.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: identityapi.ReasonGranted}, nil
}

// spec:observability-instrumentation/recorded-monitor-match-counts-are-readable-per-rule/the-cap-follows-the-deployment-s-retention
//
// TestSetRetentionDays_BoundsTheReadWindow pins the WIRING, which is the half the operator-package tests cannot see: they set the
// cap on the handler directly, so they pass just as well when nothing in the server ever calls SetMatchCountCap.
//
// Driven through the real HTTP surface rather than by reading the handler's field, because the field is unexported in another
// package and because what matters is the number an operator is shown, not where it is stored.
func TestSetRetentionDays_BoundsTheReadWindow(t *testing.T) {
	t.Parallel()
	r, _ := newPruneHarness(t, 0)
	r.detectionConfigH = operator.NewDetectionConfig(r.detectionConfigSvc, allowAllAuthZ{}, slog.New(slog.DiscardHandler))
	mux := http.NewServeMux()
	r.detectionConfigH.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	readWindow := func(t *testing.T) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			srv.URL+"/api/v1/detection-config/rule-match-counts?days=30", nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			Days int `json:"days"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return body.Days
	}

	assert.Equal(t, 30, readWindow(t), "before retention is known the constant cap stands")

	r.SetRetentionDays(7)

	assert.Equal(t, 7, readWindow(t),
		"the prune keeps 7 days, so the read surface must not claim 30: pruning and reporting share one number")
}
