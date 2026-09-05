//go:build integration

package tests

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// newRulesWithDB is newRules keeping the handle, because this test reads the table the write is supposed to stop touching.
func newRulesWithDB(t *testing.T) (*rulesbootstrap.Rules, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	r, err := rulesbootstrap.New(t.Context(), rulesbootstrap.Deps{
		DB:     db,
		Logger: slog.Default(),
		AuthZ:  allowAllAuthZ{},
	})
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r, db
}

func evalStatsRowCount(t *testing.T, db *sqlx.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetContext(t.Context(), &n, `SELECT COUNT(*) FROM detection_rule_eval_stats`))
	return n
}

// TestEvalStatsWiring_RecorderIsBufferedAndRunFlushesIt is a WIRING test, and it exists because the two ways this change can be
// silently undone are both missing-line-in-a-list shapes rather than broken logic.
//
// If the accessor handed out the store again, every batch would write to the database exactly as before and no unit test of the
// buffer would notice, because the buffer would still work perfectly in isolation. If the flush loop were dropped from Run, the
// numbers would simply stop appearing and the same unit tests would still pass. So both are asserted here, against a real
// database, through the accessor the detection context actually consumes.
func TestEvalStatsWiring_RecorderIsBufferedAndRunFlushesIt(t *testing.T) {
	t.Parallel()

	r, db := newRulesWithDB(t)
	recorder := r.RuleEvalStatsRecorder()
	require.NotNil(t, recorder)

	// What the engine does once per batch.
	for range 25 {
		require.NoError(t, recorder.RecordRuleEvalStats(t.Context(), rulesapi.RuleEvalStats{
			{RuleID: "suspicious_exec", Evaluations: 1, EvalNs: 1000, MaxEvalNs: 1000},
			{RuleID: "dyld_insert", Evaluations: 1, RetryableMisses: 1, EvalNs: 500, MaxEvalNs: 500},
		}))
	}

	// Issue #837's first acceptance criterion, asserted against the table rather than by counting calls to a fake.
	require.Zero(t, evalStatsRowCount(t, db),
		"25 batches must have written nothing; the drain path performing this write is what capped ingest")

	// Run's flush loop is what makes the numbers appear at all, so cancelling it must produce them rather than lose them.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	// Cancelled immediately: the flush under test is the one on shutdown, not a tick, so this must not depend on the interval.
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	assert.Equal(t, 2, evalStatsRowCount(t, db), "one row per rule, written by the flush rather than by any batch")

	var evaluations, misses, sum, worst int64
	require.NoError(t, db.GetContext(t.Context(), &evaluations,
		`SELECT evaluations FROM detection_rule_eval_stats WHERE rule_id = 'suspicious_exec'`))
	require.NoError(t, db.GetContext(t.Context(), &misses,
		`SELECT retryable_misses FROM detection_rule_eval_stats WHERE rule_id = 'dyld_insert'`))
	require.NoError(t, db.GetContext(t.Context(), &sum,
		`SELECT eval_ns_sum FROM detection_rule_eval_stats WHERE rule_id = 'suspicious_exec'`))
	require.NoError(t, db.GetContext(t.Context(), &worst,
		`SELECT eval_ns_max FROM detection_rule_eval_stats WHERE rule_id = 'suspicious_exec'`))

	assert.Equal(t, int64(25), evaluations, "the totals must be exact, not sampled; that was the reason for rejecting sampling")
	assert.Equal(t, int64(25), misses, "retryable misses are rare and decision-relevant, so none may be dropped")
	assert.Equal(t, int64(25_000), sum)
	assert.Equal(t, int64(1000), worst, "the worst single evaluation, not the sum and not the last")
}
