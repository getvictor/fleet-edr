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
		claimed, stamp, err := log.ClaimForHost(t.Context(), hostID, batchLimit)
		require.NoError(t, err)
		require.NotEmpty(t, claimed, "the failing batch must still be offered on every attempt")
		ids = ids[:0]
		for _, e := range claimed {
			ids = append(ids, e.EventID)
		}
		setAside, _, err := log.Nack(t.Context(), ids, stamp)
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
	claimed, stamp, err := log.ClaimForHost(t.Context(), host, batch)
	require.NoError(t, err)
	require.NotEmpty(t, claimed)
	var again []string
	for _, e := range claimed {
		again = append(again, e.EventID)
	}
	setAside, _, err := log.Nack(t.Context(), again, stamp)
	require.NoError(t, err)
	// EXACTLY the batch, not merely positive. A caller decides whether a whole batch was withdrawn by comparing this against the
	// number of events it handed over (#843), so an under-count here reads as a partial withdrawal and silently discards what
	// that batch matched. "Positive" cannot see that, and every test above stays green while it happens.
	assert.Equal(t, int64(len(again)), setAside,
		"past both bounds the whole batch must be set aside, and the count must say so exactly")

	next, _, err := log.ClaimForHost(t.Context(), host, batch)
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

	claimed, transientStamp, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.NotEmpty(t, claimed, "inside the duration window the batch is still retried, however many attempts it has taken")

	// The condition clears and the batch acknowledges like any other.
	held, ackErr := log.Ack(t.Context(), []string{"transient-1"}, transientStamp)
	require.NoError(t, ackErr)
	require.True(t, held)
	after, _, err := log.ClaimForHost(t.Context(), host, 10)
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
	claimed, stamp, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	setAside, _, err := log.Nack(t.Context(), []string{"quiet-1"}, stamp)
	require.NoError(t, err)
	require.Zero(t, setAside)

	// Then the host goes quiet for an hour, so the duration bound is well past.
	ageFirstFailure(t, db, []string{"quiet-1"}, time.Hour)

	claimed, stamp, err = log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1, "the event is still claimable, since one failure is not a deterministic failure")
	setAside, _, err = log.Nack(t.Context(), []string{"quiet-1"}, stamp)
	require.NoError(t, err)
	assert.Zero(t, setAside,
		"two attempts is not enough to call this deterministic, however long ago the first one was: the duration bound alone "+
			"would withdraw events over a single failure the next attempt might have processed")

	again, _, err := log.ClaimForHost(t.Context(), host, 10)
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
	claimed, stamp, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.NotEmpty(t, claimed)
	setAside, _, err := log.Nack(t.Context(), []string{"retained-1"}, stamp)
	require.NoError(t, err)
	require.Equal(t, int64(1), setAside)

	var row struct {
		Processed    int    `db:"processed"`
		Payload      string `db:"payload"`
		Attempts     int    `db:"attempts"`
		SetAsideAtNs int64  `db:"set_aside_at_ns"`
	}
	require.NoError(t, db.GetContext(t.Context(), &row,
		"SELECT processed, payload, attempts, set_aside_at_ns FROM event_queue WHERE event_id = 'retained-1'"),
		"the entry must still exist, or which events were withdrawn is unrecoverable")
	assert.Equal(t, 3, row.Processed, "set aside, which is a state and not a deletion")
	assert.JSONEq(t, `{"pid":1}`, row.Payload, "with its payload intact")
	assert.Positive(t, row.Attempts, "and the attempt count that explains why")
	assert.InDelta(t, time.Now().UnixNano(), row.SetAsideAtNs, float64(time.Minute),
		"stamped when it was withdrawn, which is the clock the retention sweep reads")

	// The seam, asserted as behaviour rather than as a column value. Nack stamping the withdrawal and PruneSetAside ageing on that
	// stamp were tested apart, and nothing joined them: the sweep test plants rows with an explicit stamp, so dropping the stamp
	// from Nack left set_aside_at_ns at 0, read as withdrawn at the epoch, and swept every set-aside entry on the first pass. That
	// deletes the record of what every host stopped processing immediately, and it passed the whole file.
	kept, err := log.PruneSetAside(t.Context(), 30, 100)
	require.NoError(t, err)
	assert.Zero(t, kept, "an entry withdrawn moments ago is inside any sane retention window")
	var still int
	require.NoError(t, db.GetContext(t.Context(), &still,
		"SELECT COUNT(*) FROM event_queue WHERE event_id = 'retained-1'"))
	assert.Equal(t, 1, still, "so the operator still has something to look at")
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/events-set-aside-do-not-accumulate-without-bound
// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/the-retention-window-starts-when-events-are-withdrawn
//
// TestPruneSetAside covers the retention sweep from both sides, and the disabled case.
//
// Both sides, because a sweep that deleted everything would pass a test that only checked the old entry was gone, and would erase
// the window an operator has to look at what a host stopped processing. The disabled case, because reading a zero retention as
// "keep nothing older than now" would delete every set-aside entry on the first sweep of a deployment that asked to keep them.
//
// It also pins WHICH clock the sweep reads, because the obvious wrong one passes every other assertion here.
func TestPruneSetAside(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	ctx := t.Context()

	// Written straight to the table: the recorder always stamps "now", and this needs entries either side of a boundary.
	// The third row is the one that separates the two clocks: withdrawn an hour ago, but first failed longer ago than the whole
	// window, which is the shape a host that fails a batch and then goes offline for a month produces. Ageing the sweep on first
	// failure sweeps it immediately and leaves nothing to inspect.
	for _, tc := range []struct {
		id             string
		setAsideAge    time.Duration
		firstFailedAge time.Duration
	}{
		{"stale-aside", 40 * 24 * time.Hour, 40 * 24 * time.Hour},
		{"fresh-aside", 1 * time.Hour, 1 * time.Hour},
		{"long-failing-recently-withdrawn", 1 * time.Hour, 90 * 24 * time.Hour},
	} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO event_queue (event_id, host_id, timestamp_ns, event_type, payload, processed, first_failed_at_ns, set_aside_at_ns)
			VALUES (?, 'host-prune', 1000, 'exec', '{}', 3, ?, ?)`,
			tc.id, time.Now().Add(-tc.firstFailedAge).UnixNano(), time.Now().Add(-tc.setAsideAge).UnixNano())
		require.NoError(t, err)
	}

	deleted, err := log.PruneSetAside(ctx, 30, 100)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "exactly the entry past the window")

	var remaining []string
	require.NoError(t, db.SelectContext(ctx, &remaining,
		"SELECT event_id FROM event_queue WHERE processed = 3 ORDER BY event_id"))
	assert.Equal(t, []string{"fresh-aside", "long-failing-recently-withdrawn"}, remaining,
		"both entries inside the window are kept, including the one whose first failure predates it: the window an operator has "+
			"to look starts when the events were withdrawn, and attempts accrue only while a host is online, so the two clocks "+
			"diverge without bound")

	t.Run("a non-positive retention keeps them indefinitely", func(t *testing.T) {
		for _, retention := range []int{0, -1} {
			gone, pErr := log.PruneSetAside(ctx, retention, 100)
			require.NoError(t, pErr)
			assert.Zerof(t, gone, "retention %d must disable the sweep, not delete everything", retention)
		}
	})
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/a-set-aside-event-stops-counting-as-backlog
//
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

// spec:server-event-ingestion/acknowledgement-requires-still-holding-the-claim/a-nack-from-a-lost-claim-withdraws-nothing
//
// TestNackRequiresStillHoldingTheClaim covers issue #840, which is #817's defect on the other transition. Ack became conditional
// on the claim it was issued for; Nack stayed conditional on an event's STATE, which is not the same question.
//
// What a stale nack cost was worse than it read, and the two assertions below are the two halves of it. It reset a claim the
// replacement held, so the replacement's own Ack was then refused (Ack checks the stamp) and its work was redone by whoever
// claimed the row next. And it counted an attempt against that claim, on a failure the replacement had not had, which walks the
// row toward the bounds that withdraw it: the attempt count lives on the row, so one stale nack is enough where ordinary failures
// have already brought it to within one.
//
// Driven through the store rather than a fake, because the property is the SQL predicate and a fake would assert only that this
// test passes the stamp it was given.
func TestNackRequiresStillHoldingTheClaim(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-840"

	enqueue(t, log, host, "e-840", 1_000)

	first, firstStamp, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.Len(t, first, 1)

	// Age the claim past its lease, which is what an over-running fold does to itself, and let a replacement take the row.
	_, err = db.ExecContext(t.Context(), "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "e-840")
	require.NoError(t, err)

	second, secondStamp, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.Len(t, second, 1, "an expired claim is re-offered, which is the premise")
	require.NotEqual(t, firstStamp, secondStamp, "the re-claim must stamp its own identity, or nothing can tell them apart")

	// The stale attempt nacks the row it no longer owns.
	setAside, held, err := log.Nack(t.Context(), []string{"e-840"}, firstStamp)
	require.NoError(t, err)
	assert.Zero(t, setAside, "it withdrew nothing, because it owned nothing")
	assert.False(t, held,
		"and it must be TOLD so: zero is also what a held batch gets when no event reached its bounds, so without this the "+
			"only silent way to lose a claim would be the one this change created")

	var state struct {
		Processed int   `db:"processed"`
		Attempts  int   `db:"attempts"`
		ClaimedAt int64 `db:"claimed_at_ns"`
	}
	require.NoError(t, db.GetContext(t.Context(), &state,
		"SELECT processed, attempts, claimed_at_ns FROM event_queue WHERE event_id = ?", "e-840"))

	assert.Equal(t, 2, state.Processed, "the replacement's claim must survive: a reset here is what made its Ack fail")
	assert.Equal(t, secondStamp, state.ClaimedAt, "and survive as ITS claim, not merely as some claim")
	assert.Zero(t, state.Attempts,
		"no attempt may be counted against a claim that did not fail: the count lives on the row and walks it toward withdrawal")

	// The replacement still owns the row, so its own transitions still work. Without this the test would pass against a Nack that
	// refused everything.
	acked, err := log.Ack(t.Context(), []string{"e-840"}, secondStamp)
	require.NoError(t, err)
	assert.True(t, acked, "the claim the stale nack did not disturb must still be able to acknowledge")
}

// spec:server-event-ingestion/acknowledgement-requires-still-holding-the-claim/a-nack-acts-only-on-the-events-its-claim-holds
//
// TestNackTouchesOnlyTheEventsTheClaimHolds is the half of issue #840 that ownership on the lookup alone does not give you.
//
// Refusing a nack that owns NOTHING is the easy case, and the test above covers it. This is the mixed one: a caller hands over
// ids of which it owns some, which is what a batch looks like after a lease expires under it and part of the batch moves on.
// Every statement below the ownership check has to key on the owned set rather than on the ids that were asked for, and both
// statements are exercised here because they can be wrong independently: the reset would clobber a live claim, and the withdrawal
// would set aside a row belonging to someone else.
//
// The events sit on different hosts because the queue's own in-flight bound will not let one host hold two claims at once, and
// Nack takes ids without a host filter, so this is the shape a caller reaches it in.
func TestNackTouchesOnlyTheEventsTheClaimHolds(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)

	enqueue(t, log, "host-mine", "e-mine", 1_000)
	enqueue(t, log, "host-theirs", "e-theirs", 1_000)
	enqueue(t, log, "host-pending", "e-pending", 1_000)

	mine, myStamp, err := log.ClaimForHost(t.Context(), "host-mine", 10)
	require.NoError(t, err)
	require.Len(t, mine, 1)

	theirs, theirStamp, err := log.ClaimForHost(t.Context(), "host-theirs", 10)
	require.NoError(t, err)
	require.Len(t, theirs, 1)
	require.NotEqual(t, myStamp, theirStamp)

	// e-pending is left unclaimed and driven right up to both bounds, so it is one nack away from being withdrawn by anyone
	// permitted to nack it. Nobody is: it is not in flight at all.
	_, err = db.ExecContext(t.Context(), "UPDATE event_queue SET attempts = ? WHERE event_id = ?", 20, "e-pending")
	require.NoError(t, err)
	ageFirstFailure(t, db, []string{"e-pending"}, time.Hour)

	// One nack naming all three, from the claim that holds only the first.
	setAside, held, err := log.Nack(t.Context(), []string{"e-mine", "e-theirs", "e-pending"}, myStamp)
	require.NoError(t, err)
	assert.Zero(t, setAside, "only e-mine was withdrawn-eligible, and it is nowhere near its bounds")
	assert.True(t, held, "it held one of them, so it did not lose its claim and must not be warned about")

	var theirState struct {
		Processed int   `db:"processed"`
		ClaimedAt int64 `db:"claimed_at_ns"`
		Attempts  int   `db:"attempts"`
	}
	require.NoError(t, db.GetContext(t.Context(), &theirState,
		"SELECT processed, claimed_at_ns, attempts FROM event_queue WHERE event_id = ?", "e-theirs"))
	assert.Equal(t, 2, theirState.Processed, "another worker's live claim must survive a nack that merely named its event")
	assert.Equal(t, theirStamp, theirState.ClaimedAt, "and survive as THEIR claim")
	assert.Zero(t, theirState.Attempts, "and carry no attempt from a failure that was not theirs")

	var pendingState int
	require.NoError(t, db.GetContext(t.Context(), &pendingState,
		"SELECT processed FROM event_queue WHERE event_id = ?", "e-pending"))
	assert.Equal(t, 0, pendingState,
		"a row at its bounds must not be withdrawn by a nack that never held it: it was never in flight for this claim")

	// And the row this claim DID hold went back for a retry, so the scoping did not simply refuse everything.
	var mineState int
	require.NoError(t, db.GetContext(t.Context(), &mineState,
		"SELECT processed FROM event_queue WHERE event_id = ?", "e-mine"))
	assert.Equal(t, 0, mineState, "the owned row is returned to the queue, which is what the nack was for")
}

// TestNackOwnershipReadFailureIsReturned pins that a failure of the ownership read reaches the caller.
//
// It matters because of what the caller does with the result. A nack returns zero when the attempt owns nothing, which is a
// normal outcome and not an error, and the processor reads that zero as "nothing was withdrawn". A read failure swallowed into
// the same zero would be indistinguishable from it, so a database outage would read as a routine superseded attempt and the
// events would sit in flight until their lease expired with nothing saying why.
func TestNackOwnershipReadFailureIsReturned(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-read-fail"

	enqueue(t, log, host, "e-read-fail", 1_000)
	claimed, stamp, err := log.ClaimForHost(t.Context(), host, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1)

	// The table is dropped rather than the pool closed, and the difference is the point: a closed pool fails at BeginTxx, which
	// is a path this already covers, while the ownership read is the first statement inside the transaction. This is scoped to
	// the per-test database testdb.Open creates, so it touches nothing shared.
	_, err = db.ExecContext(t.Context(), "DROP TABLE event_queue")
	require.NoError(t, err)

	setAside, held, err := log.Nack(t.Context(), []string{"e-read-fail"}, stamp)
	require.Error(t, err, "a failed read must not be reported as an ordinary superseded attempt")
	assert.Zero(t, setAside)
	assert.False(t, held, "and must not claim the attempt held a claim it could not check")
}
