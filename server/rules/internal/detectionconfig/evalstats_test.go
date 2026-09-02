package detectionconfig_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
)

// spec:observability-instrumentation/per-rule-evaluation-cost-is-recorded-durably/statistics-outlive-the-process-that-produced-them
//
// TestRecordAndReadRuleEvalStats pins the accumulation and the aggregate a reader actually consumes.
//
// Written as sequential steps rather than subtests for the same reason the match-counts test is: each step builds on the rows the
// previous one wrote, and accumulation across calls IS the behaviour under test. Subtests would either be serial steps in a
// costume or parallel tests racing each other's rows.
//
// The durability half is covered by reading through a SECOND Store over the same database. That is what the requirement means by
// surviving the process: nothing is held in the store, so a fresh one over the same rows is the same situation as a restart or a
// second replica serving the read. A test cannot restart the process, and an in-process accumulator would pass a read through the
// same instance while failing the thing the requirement asks for.
func TestRecordAndReadRuleEvalStats(t *testing.T) {
	t.Parallel()
	store, db := openStore(t)
	ctx := t.Context()

	require.NoError(t, store.RecordRuleEvalStats(ctx, api.RuleEvalStats{
		{RuleID: "cheap", Evaluations: 1, EvalNs: 1_000, MaxEvalNs: 1_000},
		{RuleID: "pricey", Evaluations: 1, EvalNs: 900_000, MaxEvalNs: 900_000, RetryableMisses: 1},
	}))
	// A second batch, so the aggregate is exercised over accumulated rows rather than a single write. The slower attempt on
	// `pricey` arrives SECOND, and the faster one on the third call below arrives after it, which is what makes the max
	// meaningful: under last-write-wins the reported worst case would be whichever landed last.
	require.NoError(t, store.RecordRuleEvalStats(ctx, api.RuleEvalStats{
		{RuleID: "pricey", Evaluations: 1, EvalNs: 1_100_000, MaxEvalNs: 1_100_000},
	}))
	require.NoError(t, store.RecordRuleEvalStats(ctx, api.RuleEvalStats{
		{RuleID: "pricey", Evaluations: 1, EvalNs: 100_000, MaxEvalNs: 100_000},
	}))

	// Read through a different Store over the same rows: the durability the requirement asks for.
	fresh := detectionconfig.NewStore(db)
	rows, err := fresh.EvalStats(ctx, api.DefaultEvalStatsWindow)
	require.NoError(t, err)

	got := map[string]api.RuleEvalSummary{}
	for _, r := range rows {
		got[r.RuleID] = r
	}
	require.Len(t, got, 2, "one row per rule that evaluated")

	pricey := got["pricey"]
	assert.Equal(t, int64(3), pricey.Evaluations, "attempts accumulate across calls")
	assert.Equal(t, int64(1), pricey.RetryableMisses, "only the attempt that missed counts as a miss")
	// (900_000 + 1_100_000 + 100_000) / 3 = 700_000.
	assert.Equal(t, int64(700_000), pricey.MeanEvalNs,
		"the mean is computed from the stored sum and count, so it weights a busy day by its volume rather than averaging "+
			"per-day averages")
	assert.Equal(t, int64(1_100_000), pricey.MaxEvalNs,
		"the worst case is the largest attempt seen, not the most recent: a faster attempt landing later must not erase it")
	assert.False(t, pricey.LastSeen.IsZero(), "a row that exists has been seen")

	cheap := got["cheap"]
	assert.Equal(t, int64(1), cheap.Evaluations)
	assert.Equal(t, int64(0), cheap.RetryableMisses, "a rule that never missed reports zero rather than being absent")

	// Ordered by cost, because the read exists to answer "which rule is expensive" and a reader should not have to sort it.
	require.Len(t, rows, 2)
	assert.Equal(t, "pricey", rows[0].RuleID, "the most expensive rule comes first")
}

// TestRuleEvalStatsAcceptsTheLongestShippedRuleID is the regression for what live QA caught and every unit test above missed.
//
// The tests here name rules "cheap" and "real" because a test author picks short names, and that is exactly why none of them
// caught it: the imported SigmaHQ rules derive their ids from upstream filenames and the longest shipped one is 70 characters,
// while every rule_id column in the repo is VARCHAR(64). The first real write on the dev server failed with "Data too long for
// column 'rule_id'" for all 73 dispatched rules at once.
//
// Pinned with the actual shipped id rather than strings.Repeat("x", 70), so the test states the fact that makes the column width
// necessary. If that rule is ever renamed this test still guards the width; if a LONGER rule arrives, this is the test to update,
// which is the right place for that decision to surface.
func TestRuleEvalStatsAcceptsTheLongestShippedRuleID(t *testing.T) {
	t.Parallel()
	store, _ := openStore(t)
	ctx := t.Context()

	const longest = "proc_creation_macos_remote_access_tools_teamviewer_incoming_connection"
	require.Greater(t, len(longest), 64, "the point of this test is that the id exceeds the width every other rule_id column uses")

	require.NoError(t, store.RecordRuleEvalStats(ctx, api.RuleEvalStats{
		{RuleID: longest, Evaluations: 1, EvalNs: 10, MaxEvalNs: 10},
	}))

	rows, err := store.EvalStats(ctx, api.DefaultEvalStatsWindow)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, longest, rows[0].RuleID, "stored and read back whole, not silently truncated to 64")
}

// TestRuleEvalStatsIgnoresEntriesThatReportNoAttempt pins the fold's two drops.
//
// Both are real inputs rather than defensive padding: the api type crosses a context boundary, and an entry naming no rule cannot
// be keyed while an entry reporting no attempt would insert a row whose mean is a division by zero. Dropping them at the write is
// what lets the read divide without a guard on every row.
func TestRuleEvalStatsIgnoresEntriesThatReportNoAttempt(t *testing.T) {
	t.Parallel()
	store, _ := openStore(t)
	ctx := t.Context()

	require.NoError(t, store.RecordRuleEvalStats(ctx, api.RuleEvalStats{
		{RuleID: "", Evaluations: 5, EvalNs: 10},
		{RuleID: "no-attempts", Evaluations: 0, EvalNs: 10},
		{RuleID: "real", Evaluations: 1, EvalNs: 10, MaxEvalNs: 10},
	}))

	rows, err := store.EvalStats(ctx, api.DefaultEvalStatsWindow)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the entry describing a real attempt is stored")
	assert.Equal(t, "real", rows[0].RuleID)
}

// TestRuleEvalStatsFoldsRepeatedRulesInOneCall pins that a duplicate key inside one batch is folded before the statement, and that
// the fold takes a MAX for the worst case rather than summing it.
//
// Summing the struct field for field is the plausible mistake and it would be invisible in the totals: evaluations and the sum
// would still be right, and only the worst case would silently become the total of the two durations.
func TestRuleEvalStatsFoldsRepeatedRulesInOneCall(t *testing.T) {
	t.Parallel()
	store, _ := openStore(t)
	ctx := t.Context()

	require.NoError(t, store.RecordRuleEvalStats(ctx, api.RuleEvalStats{
		{RuleID: "twice", Evaluations: 1, EvalNs: 300, MaxEvalNs: 300},
		{RuleID: "twice", Evaluations: 1, EvalNs: 100, MaxEvalNs: 100},
	}))

	rows, err := store.EvalStats(ctx, api.DefaultEvalStatsWindow)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, int64(2), rows[0].Evaluations)
	assert.Equal(t, int64(200), rows[0].MeanEvalNs, "(300 + 100) / 2")
	assert.Equal(t, int64(300), rows[0].MaxEvalNs, "the worst of the two, not their sum")
}

// spec:observability-instrumentation/per-rule-evaluation-cost-is-recorded-durably/statistics-older-than-the-retention-window-are-pruned
//
// TestPruneRuleEvalStats pins the retention boundary from both sides.
//
// Asserting only that old rows go would pass for a prune that deleted everything, which is the more damaging failure: it would
// erase the recent statistics an operator is actually reading while looking like it worked.
func TestPruneRuleEvalStats(t *testing.T) {
	t.Parallel()
	store, db := openStore(t)
	ctx := t.Context()

	// Written directly rather than through the recorder, because the recorder always stamps the server's current day and this
	// test needs rows on either side of a boundary.
	old := time.Now().UTC().AddDate(0, 0, -10).Format(time.DateOnly)
	recent := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	for _, tc := range []struct{ ruleID, day string }{{"stale", old}, {"fresh", recent}} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO detection_rule_eval_stats (rule_id, day, evaluations, eval_ns_sum, eval_ns_max)
			VALUES (?, ?, 1, 10, 10)`, tc.ruleID, tc.day)
		require.NoError(t, err)
	}

	deleted, err := store.PruneRuleEvalStats(ctx, 7)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "exactly the row outside the window")

	rows, err := store.EvalStats(ctx, api.MaxEvalStatsWindow)
	require.NoError(t, err)
	require.Len(t, rows, 1, "the row inside the window is kept: a prune that took both would erase what an operator reads")
	assert.Equal(t, "fresh", rows[0].RuleID)
}

// TestPruneRuleEvalStatsDisabledByNonPositiveRetention pins that the knob disables the sweep rather than pruning everything.
//
// The failure this guards against is not cosmetic: reading a zero or negative retention as "keep nothing older than now" would
// delete every row on the first sweep, in a deployment that had asked to keep them indefinitely.
func TestPruneRuleEvalStatsDisabledByNonPositiveRetention(t *testing.T) {
	t.Parallel()
	store, db := openStore(t)
	ctx := t.Context()

	oldDay := time.Now().UTC().AddDate(0, 0, -400).Format(time.DateOnly)
	_, err := db.ExecContext(ctx, `
		INSERT INTO detection_rule_eval_stats (rule_id, day, evaluations, eval_ns_sum, eval_ns_max)
		VALUES ('ancient', ?, 1, 10, 10)`, oldDay)
	require.NoError(t, err)

	for _, retention := range []int{0, -1} {
		deleted, pruneErr := store.PruneRuleEvalStats(ctx, retention)
		require.NoError(t, pruneErr)
		assert.Zerof(t, deleted, "retention %d disables pruning entirely", retention)
	}

	var count int
	require.NoError(t, db.GetContext(ctx, &count,
		`SELECT COUNT(*) FROM detection_rule_eval_stats WHERE rule_id = 'ancient'`))
	assert.Equal(t, 1, count, "a 400-day-old row survives when pruning is disabled")
}
