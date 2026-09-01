package detectionconfig_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:observability-instrumentation/monitor-mode-matches-are-recorded-durably-per-rule/counts-are-attributed-to-the-rule-and-the-host
//
// TestRecordMonitorMatches pins the attribution the promotion decision turns on.
//
// Per rule AND per host, because those are different remedies: a rule matching heavily on one machine wants an exclusion, while
// the same volume spread across the fleet means the rule itself is too broad. A per-rule total alone cannot tell them apart.
//
// Written as sequential steps rather than subtests because each builds on the rows the previous one wrote, which is the behaviour
// under test: counts accumulate. Subtests here would either have to be serial (and then they are steps wearing a costume) or
// parallel (and then they race each other's rows).
func TestRecordMonitorMatches(t *testing.T) {
	t.Parallel()
	store, db := openStore(t)
	ctx := t.Context()

	require.NoError(t, store.RecordMonitorMatches(ctx, api.MonitorTally{
		{RuleID: "imported", HostID: "host-a", Severity: "high", Count: 3},
		{RuleID: "imported", HostID: "host-b", Severity: "high", Count: 1},
		{RuleID: "other", HostID: "host-a", Severity: "low", Count: 5},
	}))

	type row struct {
		RuleID string `db:"rule_id"`
		HostID string `db:"host_id"`
		N      int    `db:"match_count"`
	}
	var rows []row
	require.NoError(t, db.SelectContext(ctx, &rows,
		`SELECT rule_id, host_id, match_count FROM detection_rule_match_counts ORDER BY rule_id, host_id`))
	assert.Equal(t, []row{
		{RuleID: "imported", HostID: "host-a", N: 3},
		{RuleID: "imported", HostID: "host-b", N: 1},
		{RuleID: "other", HostID: "host-a", N: 5},
	}, rows, "one row per rule and host, so both the total and the spread are answerable")

	// A second batch on the same day adds rather than replacing. Replacing would make the counter report the last batch's size
	// instead of the day's, which is the difference between a rate and a sample.
	require.NoError(t, store.RecordMonitorMatches(ctx, api.MonitorTally{
		{RuleID: "imported", HostID: "host-a", Severity: "high", Count: 2},
	}))
	var accumulated int
	require.NoError(t, db.GetContext(ctx, &accumulated,
		`SELECT match_count FROM detection_rule_match_counts WHERE rule_id = 'imported' AND host_id = 'host-a'`))
	assert.Equal(t, 5, accumulated, "counts accumulate across batches within a day")

	// Severities fold into one row. Severity belongs to the OTel series, where it exists to line up with edr.alerts.created; this
	// table answers how often and how widely, and splitting rows by a severity an override can change mid-window would fragment
	// both answers.
	require.NoError(t, store.RecordMonitorMatches(ctx, api.MonitorTally{
		{RuleID: "folded", HostID: "host-a", Severity: "high", Count: 1},
		{RuleID: "folded", HostID: "host-a", Severity: "critical", Count: 2},
	}))
	var folded []row
	require.NoError(t, db.SelectContext(ctx, &folded,
		`SELECT rule_id, host_id, match_count FROM detection_rule_match_counts WHERE rule_id = 'folded'`))
	require.Len(t, folded, 1)
	assert.Equal(t, 3, folded[0].N)

	// Out-of-order writes must not narrow the recorded window. Detection runs AFTER the per-host claim lock is released, so two
	// batches for one (rule, host) can reach this write concurrently and land in either order.
	//
	// Both stored timestamps are pushed into the FUTURE, which is what makes the two halves distinguishable. A write now is then
	// earlier than both, so a correct upsert moves first_seen BACK to it (the window really did start earlier) and leaves
	// last_seen alone (the window really did extend later). Backdating instead would leave both untouched under either rule, and
	// the assertion would pass against an implementation that never updates first_seen at all.
	future := time.Now().UTC().Add(2 * time.Hour)
	_, err := db.ExecContext(ctx, `UPDATE detection_rule_match_counts
		SET first_seen = ?, last_seen = ? WHERE rule_id = 'imported' AND host_id = 'host-a'`, future, future)
	require.NoError(t, err)

	require.NoError(t, store.RecordMonitorMatches(ctx, api.MonitorTally{
		{RuleID: "imported", HostID: "host-a", Severity: "high", Count: 1},
	}))
	var window struct {
		First time.Time `db:"first_seen"`
		Last  time.Time `db:"last_seen"`
	}
	require.NoError(t, db.GetContext(ctx, &window,
		`SELECT first_seen, last_seen FROM detection_rule_match_counts WHERE rule_id = 'imported' AND host_id = 'host-a'`))
	assert.Less(t, window.First, time.Now().UTC().Add(time.Hour),
		"an earlier write widens the window backwards rather than being ignored")
	assert.Greater(t, window.Last, time.Now().UTC().Add(time.Hour),
		"and an earlier write must not drag last_seen back")

	// An empty or degenerate tally writes nothing rather than a zero row, so a rule that matched nothing never appears as one
	// that matched and was counted at zero.
	before := countRows(ctx, t, db)
	require.NoError(t, store.RecordMonitorMatches(ctx, nil))
	require.NoError(t, store.RecordMonitorMatches(ctx, api.MonitorTally{
		{RuleID: "", HostID: "host-a", Count: 1},
		{RuleID: "r", HostID: "", Count: 1},
		{RuleID: "r", HostID: "host-a", Count: 0},
	}))
	assert.Equal(t, before, countRows(ctx, t, db))
}

// spec:observability-instrumentation/monitor-mode-matches-are-recorded-durably-per-rule/counts-older-than-the-retention-window-are-pruned
//
// TestPruneMatchCounts pins that the table is bounded, and that the knob's disabled value disables the prune rather than pruning
// everything, which is the failure that would silently erase the record this feature exists to keep.
func TestPruneMatchCounts(t *testing.T) {
	t.Parallel()
	store, db := openStore(t)
	ctx := t.Context()

	day := func(daysAgo int) string { return time.Now().UTC().AddDate(0, 0, -daysAgo).Format(time.DateOnly) }
	for _, daysAgo := range []int{0, 5, 40} {
		_, err := db.ExecContext(ctx,
			`INSERT INTO detection_rule_match_counts (rule_id, host_id, day, match_count) VALUES (?, 'host-a', ?, 1)`,
			"rule-"+day(daysAgo), day(daysAgo))
		require.NoError(t, err)
	}
	require.Equal(t, 3, countRows(ctx, t, db))

	deleted, err := store.PruneMatchCounts(ctx, 0)
	require.NoError(t, err)
	assert.Zero(t, deleted)
	assert.Equal(t, 3, countRows(ctx, t, db), "the disabled value must not be read as prune everything")

	deleted, err = store.PruneMatchCounts(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
	assert.Equal(t, 2, countRows(ctx, t, db), "rows past the window go, rows inside it stay")

	// Idempotent, which is what lets every replica run the sweep without a leader lock: a second pass deletes what the first
	// already did, namely nothing.
	deleted, err = store.PruneMatchCounts(ctx, 30)
	require.NoError(t, err)
	assert.Zero(t, deleted)
}

// TestPruneMatchCountsBatches pins that the sweep keeps going past one batch.
//
// The batch bound exists so one pass cannot take an unbounded row-lock and undo-log footprint while every replica contends on the
// same range, which is a real risk the first time a deployment lowers its retention. A loop that stopped after the first batch
// would leave the backlog behind forever, and one that never stopped would spin: this pins the boundary by using more rows than a
// single batch holds.
func TestPruneMatchCountsBatches(t *testing.T) {
	t.Parallel()
	store, db := openStore(t)
	ctx := t.Context()

	const overOneBatch = 1001
	old := time.Now().UTC().AddDate(0, 0, -40).Format(time.DateOnly)
	values := make([]string, 0, overOneBatch)
	args := make([]any, 0, overOneBatch*2)
	for i := range overOneBatch {
		values = append(values, "(?, ?, ?, 1)")
		args = append(args, fmt.Sprintf("rule-%04d", i), "host-a", old)
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO detection_rule_match_counts (rule_id, host_id, day, match_count) VALUES `+strings.Join(values, ", "), args...)
	require.NoError(t, err)
	require.Equal(t, overOneBatch, countRows(ctx, t, db))

	deleted, err := store.PruneMatchCounts(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, int64(overOneBatch), deleted, "the sweep continues past the first batch rather than stopping at its bound")
	assert.Zero(t, countRows(ctx, t, db))
}

// countRows reports how many counter rows exist, which several assertions compare before and after.
func countRows(ctx context.Context, t *testing.T, db *sqlx.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetContext(ctx, &n, `SELECT COUNT(*) FROM detection_rule_match_counts`))
	return n
}

// spec:observability-instrumentation/recorded-monitor-match-counts-are-readable-per-rule/counts-are-readable-per-rule-over-a-window
//
// TestMatchCounts covers the read the promotion decision is actually made against.
//
// The three numbers are the point: matches alone cannot separate a rule that is noisy on one machine, which wants an exclusion,
// from one that is too broad across the fleet, which wants leaving in monitor.
func TestMatchCounts(t *testing.T) {
	t.Parallel()
	store, db := openStore(t)
	ctx := t.Context()

	day := func(daysAgo int) string { return time.Now().UTC().AddDate(0, 0, -daysAgo).Format(time.DateOnly) }
	seed := func(ruleID, hostID string, daysAgo, count int) {
		t.Helper()
		_, err := db.ExecContext(ctx, `INSERT INTO detection_rule_match_counts
			(rule_id, host_id, day, match_count, last_seen) VALUES (?, ?, ?, ?, ?)`,
			ruleID, hostID, day(daysAgo), count, time.Now().UTC().AddDate(0, 0, -daysAgo))
		require.NoError(t, err)
	}
	// "narrow" is heavy on one host; "broad" is light across three. Equal totals, opposite remedies.
	//
	// narrow is seeded across THREE DAYS on one host, which is what makes the host count a real assertion: with one row per host
	// a plain COUNT(host_id) and COUNT(DISTINCT host_id) agree, so a fixture like that cannot tell the two apart.
	seed("narrow", "host-a", 1, 30)
	seed("narrow", "host-a", 2, 30)
	seed("narrow", "host-a", 3, 30)
	seed("broad", "host-a", 1, 30)
	seed("broad", "host-b", 2, 30)
	seed("broad", "host-c", 3, 30)
	// Outside the default week, so it must not appear in a 7-day read.
	seed("stale", "host-a", 20, 500)
	// Outside the CAP, so a request for a window past the cap must not reach it. Without a row older than the cap, clamping and
	// not clamping return the same rows and the clamp assertion below proves nothing.
	seed("ancient", "host-a", 45, 700)

	got, err := store.MatchCounts(ctx, api.DefaultMatchCountWindow)
	require.NoError(t, err)
	require.Len(t, got, 2, "a rule whose matches all fall outside the window is absent, not zero")

	byRule := map[string]api.RuleMatchCount{}
	for _, r := range got {
		byRule[r.RuleID] = r
	}
	assert.Equal(t, int64(90), byRule["narrow"].Matches)
	assert.Equal(t, int64(1), byRule["narrow"].Hosts, "one noisy host is an exclusion, not a broad rule")
	assert.Equal(t, int64(90), byRule["broad"].Matches)
	assert.Equal(t, int64(3), byRule["broad"].Hosts, "same volume, three hosts: the rule itself is too broad")
	// Pinned as the MOST RECENT contributing row, not merely "populated": broad's three rows are 1, 2 and 3 days old, so
	// swapping MAX(last_seen) for MIN(last_seen) would still leave this non-zero. Recency is one of the three signals the
	// endpoint promises, and "matched heavily but has since gone quiet" is the case it exists to distinguish.
	assert.WithinDuration(t, time.Now().UTC().AddDate(0, 0, -1), byRule["broad"].LastSeen, time.Hour,
		"last_seen is the newest contributing row, not the oldest")
	assert.Greater(t, byRule["broad"].LastSeen.Unix(), time.Now().UTC().AddDate(0, 0, -2).Unix(),
		"a MIN aggregate would report the three-day-old row instead")

	// Ordered by volume, because the rule an operator most wants to see is the loudest one.
	assert.Equal(t, "broad", got[0].RuleID, "ties break by rule id, so the order is stable")
	assert.Equal(t, "narrow", got[1].RuleID)

	// A longer window reaches the older rows. The store is handed an ALREADY-RESOLVED window (the handler owns the cap, because
	// only it knows the deployment's retention), so this asks it to honour the window it is given rather than to clamp one.
	wide, err := store.MatchCounts(ctx, api.MaxMatchCountWindow)
	require.NoError(t, err)
	assert.Len(t, wide, 3, "thirty days reaches stale but not ancient")

	widest, err := store.MatchCounts(ctx, api.MaxMatchCountWindow+90)
	require.NoError(t, err)
	assert.Len(t, widest, 4, "a wider resolved window reaches ancient: the store honours it rather than second-guessing it")
}
