//go:build integration

package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// nackOnce claims a host's oldest batch, returns it with the given carry, and reports what the queue said.
//
// The claim is taken here rather than passed in because the stamp is what identifies the attempt: a test that reused an earlier
// stamp would be exercising the superseded-attempt path (issue #840) while appearing to exercise this one.
func nackOnce(t *testing.T, log visibilityapi.EventLog, hostID string, batchLimit int, carry []byte) visibilityapi.NackResult {
	t.Helper()
	claimed, stamp, err := log.ClaimForHost(t.Context(), hostID, batchLimit)
	require.NoError(t, err)
	require.NotEmpty(t, claimed, "the batch must still be offered, or the attempt under test never happens")
	ids := make([]string, 0, len(claimed))
	for _, e := range claimed {
		ids = append(ids, e.EventID)
	}
	nacked, err := log.Nack(t.Context(), ids, stamp, carry)
	require.NoError(t, err)
	return nacked
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-value-survives-the-attempt-that-supplied-it
// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-later-value-replaces-the-one-it-supersedes
//
// TestNackCarriesAValueAcrossAttempts is the queue half of issue #893.
//
// The attempt that resolves something about a batch is by construction the attempt that then failed, and the attempt that ends the
// batch's life can be a later one that never got that far: the retry bounds accrue on the queue entry and count every attempt,
// whichever stage failed. So the value has to survive between them, and the queue is where it can, because the nack that has one is
// already writing those rows.
//
// The nil carry on the withdrawing attempt is the point of the test rather than a convenience. It is what a fold-stage failure
// hands over, and a store that wrote the caller's bytes unconditionally would clear the value at exactly the moment it is needed
// while every other assertion here still passed.
func TestNackCarriesAValueAcrossAttempts(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-carry"
	const batch = 2

	enqueue(t, log, host, "carry-1", 1_000)
	enqueue(t, log, host, "carry-2", 1_001)

	first := []byte(`{"v":1,"matches":[{"rule_id":"imported","count":2}]}`)
	require.Zero(t, nackOnce(t, log, host, batch, first).SetAside, "the first attempt is nowhere near its bounds")

	// Enough further attempts to pass the attempt bound, every one of them supplying nothing, which is what a failure before
	// evaluation looks like.
	for range 19 {
		require.Zero(t, nackOnce(t, log, host, batch, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"carry-1", "carry-2"}, 16*time.Minute)

	withdrawing := nackOnce(t, log, host, batch, nil)
	require.Equal(t, int64(batch), withdrawing.SetAside, "past both bounds the whole batch is withdrawn")
	assert.Equal(t, string(first), string(withdrawing.CarriedTally),
		"the withdrawing attempt supplied nothing and must still be given what the first attempt resolved")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-later-value-replaces-the-one-it-supersedes
//
// A later value replaces its predecessor rather than accumulating beside it. The store writes to one deterministically chosen row
// of the batch precisely so this holds: a carrier picked per call could leave two rows each holding a different attempt's value,
// and which one came back would depend on which row the read happened to find.
func TestNackKeepsOnlyTheLatestValue(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-latest"
	const batch = 2

	enqueue(t, log, host, "latest-1", 1_000)
	enqueue(t, log, host, "latest-2", 1_001)

	require.Zero(t, nackOnce(t, log, host, batch, []byte(`{"v":1,"matches":[{"count":1}]}`)).SetAside)
	superseding := []byte(`{"v":1,"matches":[{"count":9}]}`)
	require.Zero(t, nackOnce(t, log, host, batch, superseding).SetAside)

	for range 18 {
		require.Zero(t, nackOnce(t, log, host, batch, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"latest-1", "latest-2"}, 16*time.Minute)

	withdrawing := nackOnce(t, log, host, batch, nil)
	require.Equal(t, int64(batch), withdrawing.SetAside)
	assert.Equal(t, string(superseding), string(withdrawing.CarriedTally), "the later value is the one that survives")

	// And exactly one row holds it, which is what makes "the later value" a well-defined thing to return at all.
	var carrying int
	require.NoError(t, db.GetContext(t.Context(), &carrying,
		"SELECT COUNT(*) FROM event_queue WHERE event_id IN ('latest-1', 'latest-2') AND monitor_tally IS NOT NULL"))
	assert.Equal(t, 1, carrying, "one row carries the batch's value, so a second attempt overwrote rather than added")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-batch-that-is-coming-back-is-given-nothing
//
// A batch that is coming back will be processed again and resolve its own value, so handing this one out before the batch's last
// word would count it twice. The partial case is asserted alongside because it is why the store compares the withdrawal against
// the whole batch rather than against zero: the withdrawal predicate is per row.
func TestNackWithholdsTheValueUntilTheBatchIsWithdrawnInFull(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-partial"
	const batch = 2

	enqueue(t, log, host, "partial-1", 1_000)
	enqueue(t, log, host, "partial-2", 1_001)

	carry := []byte(`{"v":1,"matches":[{"count":3}]}`)
	require.Empty(t, nackOnce(t, log, host, batch, carry).CarriedTally,
		"this batch is coming back, so its own next attempt resolves the value again")

	for range 19 {
		require.Zero(t, nackOnce(t, log, host, batch, nil).SetAside)
	}
	// Only ONE of the two rows is old enough to pass the duration bound, so the next nack withdraws half the batch.
	ageFirstFailure(t, db, []string{"partial-1"}, 16*time.Minute)

	partial := nackOnce(t, log, host, batch, nil)
	require.Equal(t, int64(1), partial.SetAside, "one row passed both bounds and the other did not")
	assert.Empty(t, partial.CarriedTally,
		"the surviving row is claimed and processed again and this value covers it, so returning it now would count it twice")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-value-survives-the-attempt-that-supplied-it
//
// A superseded attempt cannot plant a value either. Nack acts only on the events the claim it names still holds (issue #840), and
// the carry rides in the same statement, so an attempt that outran its lease writes nothing at all rather than overwriting the
// value belonging to whoever owns the rows now.
func TestNackFromALostClaimStoresNoValue(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-lost"

	enqueue(t, log, host, "lost-1", 1_000)

	_, staleStamp, err := log.ClaimForHost(t.Context(), host, 1)
	require.NoError(t, err)
	// Age the claim past its lease, which is what an over-running attempt does to itself, and let a replacement take the row.
	_, err = db.ExecContext(t.Context(), "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "lost-1")
	require.NoError(t, err)
	replacement, _, err := log.ClaimForHost(t.Context(), host, 1)
	require.NoError(t, err)
	require.Len(t, replacement, 1, "an expired claim is re-offered, which is the premise")

	nacked, err := log.Nack(t.Context(), []string{"lost-1"}, staleStamp, []byte(`{"v":1,"matches":[{"count":7}]}`))
	require.NoError(t, err)
	require.False(t, nacked.Held, "the stale attempt owns nothing")

	var carrying int
	require.NoError(t, db.GetContext(t.Context(), &carrying,
		"SELECT COUNT(*) FROM event_queue WHERE event_id = 'lost-1' AND monitor_tally IS NOT NULL"))
	assert.Zero(t, carrying, "an attempt that owns no rows writes no value to them")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-batch-that-is-coming-back-is-given-nothing
//
// A whole withdrawal is measured against what the CALLER handed over, not against the subset its claim still owns. Review found
// this: mixed ownership is permitted here, so an attempt whose lease expired for part of its batch can own ONE event, have that
// event pass its bounds, and withdraw everything it owns while the rest of its batch is being reprocessed by whoever claimed it.
// The tally covers the whole batch, so handing it back there counts it alongside what those other events resolve on their own
// attempt: the double count this whole design is arranged to avoid, reached from the other side.
func TestNackWithholdsTheValueWhenOwnershipIsPartial(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-mixed"

	enqueue(t, log, host, "mixed-mine", 1_000)
	enqueue(t, log, host, "mixed-theirs", 1_001)

	// Both events go to one claim, which supplies the tally, so the value covers BOTH of them.
	carry := []byte(`{"v":1,"matches":[{"count":5}]}`)
	require.Zero(t, nackOnce(t, log, host, 2, carry).SetAside)

	// Drive the batch to its bounds, then split ownership: the second event is re-claimed by someone else, so the attempt below
	// holds only the first.
	for range 19 {
		require.Zero(t, nackOnce(t, log, host, 2, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"mixed-mine", "mixed-theirs"}, 16*time.Minute)

	claimed, myStamp, err := log.ClaimForHost(t.Context(), host, 2)
	require.NoError(t, err)
	require.Len(t, claimed, 2, "the premise is one claim over both, which is then split")
	_, err = db.ExecContext(t.Context(),
		"UPDATE event_queue SET claimed_at_ns = claimed_at_ns + 1 WHERE event_id = ?", "mixed-theirs")
	require.NoError(t, err)

	// This attempt names its whole batch and owns half of it. Every event it OWNS is withdrawn.
	nacked, err := log.Nack(t.Context(), []string{"mixed-mine", "mixed-theirs"}, myStamp, nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), nacked.SetAside, "it withdrew the one event it owned, and could not touch the other")
	require.True(t, nacked.Held)
	assert.Empty(t, nacked.CarriedTally,
		"the other half of the batch is still being processed and this value covers it, so returning it would count it twice")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-later-value-replaces-the-one-it-supersedes
//
// An attempt that supplies a value CLEARS the column on the other rows it holds, so exactly one row carries a batch's value.
//
// Review found the gap a stable carrier alone leaves: the set to choose from is not stable. Each attempt claims a fresh pending
// prefix, so consecutive attempts can own different sets and pick different carriers, and a value an earlier attempt left on a row
// a later one does not write would still be there to be read. Clearing makes the invariant a property of the write.
func TestNackClearsTheValueFromTheRowsItSupersedes(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-clear"

	enqueue(t, log, host, "clear-2", 1_001)
	enqueue(t, log, host, "clear-3", 1_002)

	// An attempt that owns only the later two events writes to the lowest id it holds, clear-2.
	stale := []byte(`{"v":1,"matches":[{"count":1}]}`)
	require.Zero(t, nackOnce(t, log, host, 2, stale).SetAside)
	var carryingRow string
	require.NoError(t, db.GetContext(t.Context(), &carryingRow,
		"SELECT event_id FROM event_queue WHERE monitor_tally IS NOT NULL AND host_id = ?", host))
	require.Equal(t, "clear-2", carryingRow, "the premise is that the first attempt's carrier is clear-2")

	// An older event now joins the claimable set, so the next attempt's set is WIDER and its carrier moves to clear-1.
	enqueue(t, log, host, "clear-1", 1_000)
	superseding := []byte(`{"v":1,"matches":[{"count":8}]}`)
	require.Zero(t, nackOnce(t, log, host, 3, superseding).SetAside)

	var carrying []string
	require.NoError(t, db.SelectContext(t.Context(), &carrying,
		"SELECT event_id FROM event_queue WHERE monitor_tally IS NOT NULL AND host_id = ? ORDER BY event_id", host))
	assert.Equal(t, []string{"clear-1"}, carrying,
		"the superseding attempt owns the new carrier AND clears the old one, so one row holds the batch's value")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-value-survives-the-attempt-that-supplied-it
//
// "No tally" has two spellings in Go, and only a nil []byte reaches SQL as NULL: an empty but non-nil one binds as an empty BLOB.
// Review found that, and it is the defect this column exists to prevent reached by a caller spelling "nothing" the other way, so
// the boundary normalizes and this pins it. The type cannot express the difference, which is why the guard is at the boundary
// rather than trusted to callers.
func TestNackTreatsAnEmptyTallyAsNoTally(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-empty"
	const batch = 2

	enqueue(t, log, host, "empty-1", 1_000)
	enqueue(t, log, host, "empty-2", 1_001)

	carry := []byte(`{"v":1,"matches":[{"count":4}]}`)
	require.Zero(t, nackOnce(t, log, host, batch, carry).SetAside)

	// An attempt that resolved nothing, spelled as an empty slice rather than nil. It must not erase what the first one supplied.
	for range 19 {
		require.Zero(t, nackOnce(t, log, host, batch, []byte{}).SetAside)
	}
	ageFirstFailure(t, db, []string{"empty-1", "empty-2"}, 16*time.Minute)

	withdrawing := nackOnce(t, log, host, batch, []byte{})
	require.Equal(t, int64(batch), withdrawing.SetAside)
	assert.Equal(t, string(carry), string(withdrawing.CarriedTally),
		"an empty slice is no tally, not an instruction to store nothing over what an earlier attempt resolved")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-later-value-replaces-the-one-it-supersedes
//
// A prefix shift at a FIXED batch limit, which review asked for by name: a late-arriving older event pushes an earlier carrier out
// of the claimable prefix, so two pending rows hold two batches' values at once and neither attempt writes the other's row.
//
// The question that state raises is whether a withdrawal can be handed a value that does not describe the events being withdrawn,
// which would count matches for events that were counted by someone else. It cannot, and the reason is the claim's shape rather
// than the clearing: the claim is a timestamp-ordered prefix of PENDING rows, so a row still holding a value is either inside the
// prefix its batch forms, where the next attempt to supply one overwrites or clears it, or has left the pending pool terminally.
// Each batch is handed its own value here, which is what makes "one row per batch" the honest statement of the invariant rather
// than "one row".
func TestNackKeepsEachBatchsValueAcrossAPrefixShift(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-shift"
	const batch = 2

	// The first batch is the whole pending set, so it is the prefix.
	enqueue(t, log, host, "shift-late-a", 2_000)
	enqueue(t, log, host, "shift-late-b", 2_001)
	older := []byte(`{"v":1,"matches":[{"count":11}]}`)
	require.Zero(t, nackOnce(t, log, host, batch, older).SetAside)

	// Two OLDER events arrive afterwards. At the same limit the prefix is now theirs, and the first batch's carrier is outside it.
	enqueue(t, log, host, "shift-early-a", 1_000)
	enqueue(t, log, host, "shift-early-b", 1_001)
	newer := []byte(`{"v":1,"matches":[{"count":22}]}`)
	require.Zero(t, nackOnce(t, log, host, batch, newer).SetAside)

	var carrying []string
	require.NoError(t, db.SelectContext(t.Context(), &carrying,
		"SELECT event_id FROM event_queue WHERE monitor_tally IS NOT NULL AND host_id = ? ORDER BY event_id", host))
	require.Equal(t, []string{"shift-early-a", "shift-late-a"}, carrying,
		"the premise: two pending rows hold two batches' values, because neither attempt's prefix contained the other's carrier")

	// The newer prefix reaches its bounds first, since the claim keeps offering it.
	for range 19 {
		require.Zero(t, nackOnce(t, log, host, batch, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"shift-early-a", "shift-early-b"}, 16*time.Minute)
	early := nackOnce(t, log, host, batch, nil)
	require.Equal(t, int64(batch), early.SetAside)
	assert.Equal(t, string(newer), string(early.CarriedTally), "the early batch is handed the value resolved over the early batch")

	// With those withdrawn, the displaced batch is the prefix again, and is handed ITS value, not the one that displaced it.
	for range 19 {
		require.Zero(t, nackOnce(t, log, host, batch, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"shift-late-a", "shift-late-b"}, 16*time.Minute)
	late := nackOnce(t, log, host, batch, nil)
	require.Equal(t, int64(batch), late.SetAside)
	assert.Equal(t, string(older), string(late.CarriedTally),
		"and the displaced batch is handed its own, so no batch is counted with another's matches")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-value-is-withheld-from-a-batch-it-was-not-supplied-for
//
// An OVERLAPPING prefix shift, and the reproducer for the double count review found. The prefix-shift test above replaces a batch
// wholesale, so the two batches share no event and nothing CAN be double counted; that shape passed while this one failed.
//
// The mechanism is two unrelated orderings. The claim takes a timestamp-ordered prefix while the carrier row is the smallest
// event_id, so a late-arriving older event can shift the prefix to one that overlaps the previous batch on a SHARED event while
// excluding its carrier. The new batch cannot clear a row it does not hold, so the old tally survives there, and the stranded
// row's own later withdrawal would report the shared event a second time. Measured: before the digest, this returned the stale
// tally.
func TestNackWithholdsAStrandedTallyFromADifferentBatch(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-overlap"
	const batch = 2

	// ids chosen so min(event_id) of the first claim is the LATER event by timestamp.
	enqueue(t, log, host, "z-shared", 1_001)
	enqueue(t, log, host, "a-carrier", 1_002)

	first := []byte(`{"v":1,"matches":[{"count":77}]}`)
	require.Zero(t, nackOnce(t, log, host, batch, first).SetAside)

	var carryingRow string
	require.NoError(t, db.GetContext(t.Context(), &carryingRow,
		"SELECT event_id FROM event_queue WHERE monitor_tally IS NOT NULL AND host_id = ?", host))
	require.Equal(t, "a-carrier", carryingRow, "premise: the carrier is the LATER event by timestamp")

	// A late-arriving OLDER event. The next prefix is {m-late, z-shared}: it overlaps the first batch on z-shared and excludes
	// the carrier, so it cannot clear it.
	enqueue(t, log, host, "m-late", 1_000)
	second := []byte(`{"v":1,"matches":[{"count":88}]}`)
	require.Zero(t, nackOnce(t, log, host, batch, second).SetAside)

	// Withdraw the overlapping batch {m-late, z-shared}.
	for range 19 {
		require.Zero(t, nackOnce(t, log, host, batch, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"m-late", "z-shared"}, 16*time.Minute)
	overlapping := nackOnce(t, log, host, batch, nil)
	require.Equal(t, int64(2), overlapping.SetAside)
	require.Equal(t, string(second), string(overlapping.CarriedTally), "z-shared's matches are counted here")

	// Now the stranded carrier is the whole remaining batch. Its stored tally covers {z-shared, a-carrier}.
	for range 20 {
		require.Zero(t, nackOnce(t, log, host, 1, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"a-carrier"}, 16*time.Minute)
	stranded := nackOnce(t, log, host, 1, nil)
	require.Equal(t, int64(1), stranded.SetAside)

	assert.Empty(t, stranded.CarriedTally,
		"this batch is {a-carrier} and the stored tally covers {z-shared, a-carrier}, so returning it counts z-shared TWICE")
}

// spec:server-event-ingestion/the-queue-carries-a-value-across-retry-attempts/a-value-is-withheld-from-a-batch-it-was-not-supplied-for
//
// The digest records the batch the tally was RESOLVED over, which is the caller's list, not the subset the claim happens to still
// own. Mixed ownership is where those differ: an attempt whose lease expired for part of its batch still evaluated the whole
// batch, so its tally covers events it no longer holds. Digesting the owned subset instead would make the tally match a later
// withdrawal of exactly that subset, and hand it matches belonging to the events it lost.
func TestNackDigestsTheBatchTheTallyCoversNotTheSubsetItOwns(t *testing.T) {
	t.Parallel()
	log, db := newEventLogWithDB(t)
	const host = "host-digest"

	enqueue(t, log, host, "dig-kept", 1_000)
	enqueue(t, log, host, "dig-lost", 1_001)

	// One claim over both, then the second event is taken by a replacement, so this attempt owns only the first while its tally
	// still covers both.
	claimed, myStamp, err := log.ClaimForHost(t.Context(), host, 2)
	require.NoError(t, err)
	require.Len(t, claimed, 2)
	_, err = db.ExecContext(t.Context(),
		"UPDATE event_queue SET claimed_at_ns = claimed_at_ns + 1 WHERE event_id = ?", "dig-lost")
	require.NoError(t, err)

	wholeBatch := []byte(`{"v":1,"matches":[{"count":33}]}`)
	nacked, err := log.Nack(t.Context(), []string{"dig-kept", "dig-lost"}, myStamp, wholeBatch)
	require.NoError(t, err)
	require.True(t, nacked.Held, "it held one of them, which is the premise")

	// The lost event is acknowledged by whoever owns it, so what remains is exactly the subset the storing attempt owned.
	_, err = db.ExecContext(t.Context(), "UPDATE event_queue SET processed = 1 WHERE event_id = ?", "dig-lost")
	require.NoError(t, err)

	for range 20 {
		require.Zero(t, nackOnce(t, log, host, 1, nil).SetAside)
	}
	ageFirstFailure(t, db, []string{"dig-kept"}, 16*time.Minute)

	withdrawing := nackOnce(t, log, host, 1, nil)
	require.Equal(t, int64(1), withdrawing.SetAside)
	assert.Empty(t, withdrawing.CarriedTally,
		"the tally covers dig-lost too, and dig-lost was accounted for by the attempt that acknowledged it")
}
