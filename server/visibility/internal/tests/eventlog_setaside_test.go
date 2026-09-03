//go:build integration

package tests

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// enqueue appends one event for a host at a given timestamp, so a test can build a host's stream in a known order. Order is what
// these tests turn on: the claim takes a host's OLDEST work first, which is why a failing batch blocks everything behind it.
func enqueue(t *testing.T, log visibilityapi.EventLog, hostID, eventID string, ts int64) {
	t.Helper()
	require.NoError(t, log.Append(t.Context(), []visibilityapi.Event{{
		EventID: eventID, HostID: hostID, TimestampNs: ts, EventType: "exec", Platform: "darwin",
		Payload: []byte(`{"pid":1}`),
	}}))
}

// ageFirstFailure moves a batch's recorded first failure into the past, which is the only way a test can reach the duration bound
// without sleeping for it. The bound is fifteen minutes by design, so waiting is not an option and faking the clock inside the
// store would mean adding an injection point that production never uses.
func ageFirstFailure(t *testing.T, db *sqlx.DB, eventIDs []string, age time.Duration) {
	t.Helper()
	query, args, err := sqlx.In("UPDATE event_queue SET first_failed_at_ns = ? WHERE event_id IN (?)",
		time.Now().Add(-age).UnixNano(), eventIDs)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), db.Rebind(query), args...)
	require.NoError(t, err)
}

// nackUntilBound nacks a claimed batch enough times to pass the attempt bound.
//
// batchLimit is explicit because it decides what the "batch" is, and getting it wrong hides the behaviour under test: a limit
// wider than the host's whole stream claims the events queued BEHIND the failing ones too, so they are set aside with it and the
// test cannot tell whether the host resumed. That is also the real collateral of setting a batch aside rather than bisecting it,
// and it is why this takes a limit rather than assuming one.
func nackUntilBound(t *testing.T, log visibilityapi.EventLog, db *sqlx.DB, hostID string, batchLimit, times int) []string {
	t.Helper()
	var ids []string
	for range times {
		claimed, err := log.ClaimForHost(t.Context(), hostID, batchLimit)
		require.NoError(t, err)
		require.NotEmpty(t, claimed, "the failing batch must still be offered on every attempt")
		ids = ids[:0]
		for _, e := range claimed {
			ids = append(ids, e.EventID)
		}
		setAside, err := log.Nack(t.Context(), ids)
		require.NoError(t, err)
		require.Zero(t, setAside, "nothing should be set aside before both bounds are passed")
	}
	return ids
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/a-deterministically-failing-batch-stops-blocking-its-host
//
// TestSetAside_UnblocksTheHost is the defect from issue #836 reproduced and fixed.
//
// The claim takes a host's oldest work first, so a nacked batch is re-offered ahead of everything newer. Before this, a batch that
// failed the same way every time was retried forever and NOTHING newer for that host was ever claimed: the process graph stopped
// advancing and every rule stopped seeing that host, not just the rule or event that failed.
//
// The assertion that matters is the second one. That the batch is set aside is mechanism; that the NEWER events are then claimed is
// the actual repair.
func TestSetAside_UnblocksTheHost(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-wedged"

	// The poison batch is oldest, so it is always claimed first.
	enqueue(t, log, host, "poison-1", 1_000)
	enqueue(t, log, host, "poison-2", 1_001)
	enqueue(t, log, host, "later-1", 2_000)

	// A batch of two, so the poison events are the batch and later-1 is genuinely queued behind it.
	const batch = 2
	ids := nackUntilBound(t, log, db, host, batch, 20)
	require.ElementsMatch(t, []string{"poison-1", "poison-2"}, ids, "the failing batch must be the two oldest events")
	ageFirstFailure(t, db, ids, 16*time.Minute)

	// One more failure, now past both bounds.
	claimed, err := log.ClaimForHost(t.Context(), host, batch)
	require.NoError(t, err)
	require.NotEmpty(t, claimed)
	var again []string
	for _, e := range claimed {
		again = append(again, e.EventID)
	}
	setAside, err := log.Nack(t.Context(), again)
	require.NoError(t, err)
	assert.Positive(t, setAside, "past both bounds the batch must be set aside rather than returned")

	next, err := log.ClaimForHost(t.Context(), host, batch)
	require.NoError(t, err)
	require.NotEmpty(t, next, "the host must resume: this is the whole point, and an empty claim here is the wedge")
	got := make([]string, 0, len(next))
	for _, e := range next {
		got = append(got, e.EventID)
	}
	assert.Contains(t, got, "later-1", "the events queued behind the poison batch must now be claimable")
	assert.NotContains(t, got, "poison-1", "a set-aside event must never be offered again")
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/a-transient-failure-is-retried-rather-than-set-aside
//
// TestSetAside_TransientFailureIsRetried pins the reason there are two bounds rather than one.
//
// At the 500ms processor tick a failing batch is attempted roughly 120 times a minute, so an attempt bound on its own converts
// every brief outage into a set-aside. This drives well past the attempt bound inside the duration window and asserts the batch is
// still being retried, then that it processes normally once the condition clears.
func TestSetAside_TransientFailureIsRetried(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-transient"

	enqueue(t, log, host, "transient-1", 1_000)

	// Three times the attempt bound, with the first failure left at "now", so only the duration bound is unmet.
	ids := nackUntilBound(t, log, db, host, 10, 60)
	require.NotEmpty(t, ids)

	claimed, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.NotEmpty(t, claimed, "inside the duration window the batch is still retried, however many attempts it has taken")

	// The condition clears and the batch acknowledges like any other.
	require.NoError(t, log.Ack(t.Context(), []string{"transient-1"}))
	after, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	assert.Empty(t, after, "an acknowledged event is terminal")
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/a-transient-failure-is-retried-rather-than-set-aside
//
// TestSetAside_OldFailureWithFewAttemptsIsRetried covers the OTHER half of "both bounds", and it was written because a mutation
// test found nothing covering it: removing the attempt bound entirely left every other test in this file passing.
//
// This is the shape the attempt bound exists for. A batch fails once, then its host goes quiet for an hour, so by the time anything
// looks at it again the duration bound is long past on a batch that has barely been tried. Setting it aside there would withdraw
// events over a single failure that a second attempt might well have processed.
func TestSetAside_OldFailureWithFewAttemptsIsRetried(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-quiet"

	enqueue(t, log, host, "quiet-1", 1_000)

	// Exactly one failure.
	claimed, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	setAside, err := log.Nack(t.Context(), []string{"quiet-1"})
	require.NoError(t, err)
	require.Zero(t, setAside)

	// Then the host goes quiet for an hour, so the duration bound is well past.
	ageFirstFailure(t, db, []string{"quiet-1"}, time.Hour)

	claimed, err = log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1, "the event is still claimable, since one failure is not a deterministic failure")
	setAside, err = log.Nack(t.Context(), []string{"quiet-1"})
	require.NoError(t, err)
	assert.Zero(t, setAside,
		"two attempts is not enough to call this deterministic, however long ago the first one was: the duration bound alone "+
			"would withdraw events over a single failure the next attempt might have processed")

	again, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	assert.Len(t, again, 1, "and it is still being retried")
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/setting-an-event-aside-does-not-delete-it
//
// TestSetAside_RetainsTheEntry pins that setting aside withdraws an event from processing rather than removing it.
//
// The entry is the only record of WHICH events a host stopped contributing; the counter says that it happened and cannot say what.
// Deleting them would have been simpler and would have thrown that away for nothing, since the event itself is in the archive
// either way.
func TestSetAside_RetainsTheEntry(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-retained"

	enqueue(t, log, host, "retained-1", 1_000)
	ids := nackUntilBound(t, log, db, host, 10, 20)
	ageFirstFailure(t, db, ids, 16*time.Minute)
	claimed, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.NotEmpty(t, claimed)
	setAside, err := log.Nack(t.Context(), []string{"retained-1"})
	require.NoError(t, err)
	require.Equal(t, int64(1), setAside)

	var row struct {
		Processed int    `db:"processed"`
		Payload   string `db:"payload"`
		Attempts  int    `db:"attempts"`
	}
	require.NoError(t, db.GetContext(t.Context(), &row,
		"SELECT processed, payload, attempts FROM event_queue WHERE event_id = 'retained-1'"),
		"the entry must still exist, or which events were withdrawn is unrecoverable")
	assert.Equal(t, 3, row.Processed, "set aside, which is a state and not a deletion")
	assert.JSONEq(t, `{"pid":1}`, row.Payload, "with its payload intact")
	assert.Positive(t, row.Attempts, "and the attempt count that explains why")
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/events-set-aside-do-not-accumulate-without-bound
//
// TestPruneSetAside covers the retention sweep from both sides, and the disabled case.
//
// Both sides, because a sweep that deleted everything would pass a test that only checked the old entry was gone, and would erase
// the window an operator has to look at a host's gap. The disabled case, because reading a zero retention as "keep nothing older
// than now" would delete every set-aside entry on the first sweep of a deployment that asked to keep them.
func TestPruneSetAside(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	ctx := t.Context()

	// Written straight to the table: the recorder always stamps "now", and this needs entries either side of a boundary.
	for _, tc := range []struct {
		id  string
		age time.Duration
	}{{"stale-aside", 40 * 24 * time.Hour}, {"fresh-aside", 1 * time.Hour}} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO event_queue (event_id, host_id, timestamp_ns, event_type, payload, processed, first_failed_at_ns)
			VALUES (?, 'host-prune', 1000, 'exec', '{}', 3, ?)`, tc.id, time.Now().Add(-tc.age).UnixNano())
		require.NoError(t, err)
	}

	deleted, err := log.PruneSetAside(ctx, 30, 100)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "exactly the entry past the window")

	var remaining []string
	require.NoError(t, db.SelectContext(ctx, &remaining,
		"SELECT event_id FROM event_queue WHERE processed = 3 ORDER BY event_id"))
	assert.Equal(t, []string{"fresh-aside"}, remaining,
		"the entry inside the window is kept: deleting it would close an operator's window on a host's gap")

	t.Run("a non-positive retention keeps them indefinitely", func(t *testing.T) {
		for _, retention := range []int{0, -1} {
			gone, pErr := log.PruneSetAside(ctx, retention, 100)
			require.NoError(t, pErr)
			assert.Zerof(t, gone, "retention %d must disable the sweep, not delete everything", retention)
		}
	})
}

// TestSetAside_IsNotCountedAsBacklog pins that a withdrawn event stops looking like work.
//
// CountPending backs the processor-backlog gauge and counted everything not acknowledged. Set-aside entries are not waiting for
// anything, so counting them would leave that gauge permanently raised by a number that never drains, which is exactly the shape
// an operator reads as a processor falling behind.
func TestSetAside_IsNotCountedAsBacklog(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	ctx := context.Background()

	enqueue(t, log, "host-gauge", "pending-1", 1_000)
	_, err := db.ExecContext(ctx, `
		INSERT INTO event_queue (event_id, host_id, timestamp_ns, event_type, payload, processed, first_failed_at_ns)
		VALUES ('aside-1', 'host-gauge', 500, 'exec', '{}', 3, ?)`, time.Now().UnixNano())
	require.NoError(t, err)

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pending, "the set-aside entry is not backlog; only the genuinely pending event is")
}
