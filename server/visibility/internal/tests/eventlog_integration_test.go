//go:build integration

// Package tests holds per-context integration tests for the visibility bounded context. They skip when EDR_TEST_DSN isn't set,
// matching the project's other DB-using tests, and exercise the EventLog work queue via visibility/bootstrap against a real MySQL.
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
	visibilitytestkit "github.com/fleetdm/edr/server/visibility/testkit"
)

func newEventLog(t *testing.T) visibilityapi.EventLog {
	t.Helper()
	log, _ := newEventLogWithDB(t)
	return log
}

func newEventLogWithDB(t *testing.T) (visibilityapi.EventLog, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, visibilitytestkit.ApplySchema(t.Context(), db))
	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
	require.NoError(t, err)
	return vis.EventLog(), db
}

func ev(id, host string, ts int64, etype string) visibilityapi.Event {
	return visibilityapi.Event{
		EventID:      id,
		HostID:       host,
		TimestampNs:  ts,
		IngestedAtNs: ts + 1,
		EventType:    etype,
		Payload:      json.RawMessage(`{"pid":1}`),
	}
}

func ids(events []visibilityapi.Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.EventID
	}
	return out
}

func TestEventLog_AppendClaimAckNack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		ev("e1", "h1", 100, "exec"),
		ev("e2", "h1", 200, "fork"),
	}))

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), pending, "both appended events are pending")

	claimed, stamp, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	require.Len(t, claimed, 2)
	assert.Equal(t, []string{"e1", "e2"}, ids(claimed))
	assert.Equal(t, int64(101), claimed[0].IngestedAtNs, "ingested_at_ns round-trips from the stored row")

	// A re-claim returns nothing: the rows are in-flight (processed = 2), not re-offered.
	again, _, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	assert.Empty(t, again)

	// Ack one, Nack the other. The ack carries the claim's stamp, which is what proves it still holds the rows (issue #817).
	held, err := log.Ack(ctx, []string{"e1"}, stamp)
	require.NoError(t, err)
	assert.True(t, held, "the claim is still held, so the ack must report that it won")
	_, nackErr := log.Nack(ctx, []string{"e2"})
	require.NoError(t, nackErr)

	pending, err = log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pending, "acked event leaves the pending count; nacked event remains")

	// The nacked event is claimable again; the acked one is not.
	reclaimed, _, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"e2"}, ids(reclaimed))
}

func TestEventLog_PlatformRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	// Append a windows, a darwin, and a legacy (no platform) row, then claim them back. The queue must carry platform through the
	// claim so the detection engine can scope rules by it; a row written before the platform column existed round-trips as the column
	// default (empty), which the engine treats as darwin.
	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		{EventID: "win", HostID: "h1", TimestampNs: 100, IngestedAtNs: 101, EventType: "exec", Platform: "windows", Payload: json.RawMessage(`{"pid":1}`)},
		{EventID: "mac", HostID: "h1", TimestampNs: 200, IngestedAtNs: 201, EventType: "exec", Platform: "darwin", Payload: json.RawMessage(`{"pid":2}`)},
		{EventID: "leg", HostID: "h1", TimestampNs: 300, IngestedAtNs: 301, EventType: "exec", Payload: json.RawMessage(`{"pid":3}`)},
	}))

	claimed, _, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	require.Len(t, claimed, 3)
	byID := make(map[string]string, len(claimed))
	for _, e := range claimed {
		byID[e.EventID] = e.Platform
	}
	assert.Equal(t, "windows", byID["win"])
	assert.Equal(t, "darwin", byID["mac"])
	assert.Empty(t, byID["leg"], "a row written with no platform round-trips as the column default; intake normalizes to darwin upstream")
}

func TestEventLog_IdempotentAppend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	batch := []visibilityapi.Event{ev("dup", "h1", 100, "exec")}
	require.NoError(t, log.Append(ctx, batch))
	require.NoError(t, log.Append(ctx, batch), "re-appending the same event_id is a no-op, not an error")

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pending, "the duplicate event_id is not enqueued twice")
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/a-claim-never-spans-hosts
//
// A claim never spans hosts (issue #717), and within a host it is timestamp-ordered so the graph builder sees a pid's fork before its
// exec. PendingHosts orders by each host's oldest claimable event, which is what keeps a host with a long-waiting backlog from being
// starved by a busier one.
func TestEventLog_ClaimIsHostScopedAndOrdered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	// hostB's rows are appended first but hostA holds the oldest event, so hostA must be offered first.
	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		ev("b2", "hostB", 400, "exec"),
		ev("a1", "hostA", 100, "exec"),
		ev("b1", "hostB", 200, "exec"),
		ev("a2", "hostA", 300, "exec"),
	}))

	hosts, err := log.PendingHosts(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"hostA", "hostB"}, hosts, "hosts are offered oldest-claimable-event first")

	first, _, err := log.ClaimForHost(ctx, "hostA", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"a1", "a2"}, ids(first), "one host's events, in timestamp order, and no other host's")

	second, _, err := log.ClaimForHost(ctx, "hostB", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"b1", "b2"}, ids(second), "a claim for another host is disjoint from the first")

	// With hostA fully in flight, only hostB's rows could still be claimable, and they are in flight too.
	drained, err := log.PendingHosts(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, drained, "a host whose rows are all in flight is not offered again until its claim expires")
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/a-claim-stops-at-a-host-s-oldest-in-flight-event
//
// An in-flight row does not match the claimable predicate, so without an explicit floor it is a HOLE in the host's stream rather than
// a stop sign: a claimer that died between claiming a fork and flushing it would let the next claimer take the following exec and fold
// it as an exec with no fork, which is exactly the #717 defect that scoping the claim to one host is meant to close. The claim must
// therefore refuse to reach past the host's oldest unexpired in-flight event, and must not reclaim it either: another worker may still
// be alive and mid-flush, so the only safe outcome is to leave that host alone until the lease expires.
// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/a-claim-bound-cannot-be-defeated-by-an-extreme-timestamp
//
// The "nothing in flight" case was first encoded as a sentinel timestamp, and that encoding produced two edges in a row on
// agent-supplied values: an exclusive bound against math.MaxInt64 stranded a row stamped exactly there (unclaimable forever, and its
// host stayed in the candidate list burning a cycle every pass), and shifting the floor a tick below the in-flight row underflowed for
// math.MinInt64, wrapping to MaxInt64 and removing the bound altogether. Queue timestamps come from agent payloads, so neither is
// merely theoretical. These pin both ends now that the bound carries a flag instead of a sentinel.
func TestEventLog_ClaimBoundSurvivesExtremeTimestamps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("an event stamped MaxInt64 is still claimable", func(t *testing.T) {
		t.Parallel()
		log, _ := newEventLogWithDB(t)
		require.NoError(t, log.Append(ctx, []visibilityapi.Event{ev("max-ts", "h-max", math.MaxInt64, "exec")}))

		claimed, _, err := log.ClaimForHost(ctx, "h-max", 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"max-ts"}, ids(claimed),
			"a sentinel-valued timestamp must not be unclaimable: it would never drain and would keep its host in the hint forever")
	})

	t.Run("an in-flight event stamped MinInt64 still bounds the claim", func(t *testing.T) {
		t.Parallel()
		log, _ := newEventLogWithDB(t)
		require.NoError(t, log.Append(ctx, []visibilityapi.Event{
			ev("min-fork", "h-min", math.MinInt64, "fork"),
			ev("min-exec", "h-min", 500, "exec"),
		}))

		inFlight, _, err := log.ClaimForHost(ctx, "h-min", 1)
		require.NoError(t, err)
		require.Equal(t, []string{"min-fork"}, ids(inFlight), "the oldest event is claimed first")

		behind, _, err := log.ClaimForHost(ctx, "h-min", 10)
		require.NoError(t, err)
		assert.Empty(t, behind,
			"an extreme in-flight timestamp must not underflow the floor into removing the bound: min-exec would leapfrog min-fork")
	})
}

func TestEventLog_ClaimStopsAtOldestInFlightEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log, db := newEventLogWithDB(t)

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		ev("gap-fork", "h-gap", 100, "fork"),
		ev("gap-exec", "h-gap", 200, "exec"),
		ev("gap-exit", "h-gap", 300, "exit"),
	}))

	// One claimer takes only the oldest event, then stops responding: the fork is in flight and its exec is still queued.
	inFlight, _, err := log.ClaimForHost(ctx, "h-gap", 1)
	require.NoError(t, err)
	require.Equal(t, []string{"gap-fork"}, ids(inFlight), "the oldest event is claimed first")

	// The host still owns never-claimed rows, so a hint that asked only "is anything unclaimed" would offer it. It must not: every
	// claim against it returns empty until the lease expires, and a candidate slot spent on it is a slot no host with work can use.
	hosts, err := log.PendingHosts(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, hosts, "a host whose only unclaimed events sit behind an in-flight one has no claimable work and is not a candidate")

	behind, _, err := log.ClaimForHost(ctx, "h-gap", 10)
	require.NoError(t, err)
	assert.Empty(t, behind,
		"events behind an unexpired in-flight event must not be claimed: folding gap-exec without gap-fork is the #717 defect")

	// Simulate the holder having died: backdate its claim past the lease. Nothing reclaimed it while the lease was live.
	_, err = db.ExecContext(ctx, "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "gap-fork")
	require.NoError(t, err)

	released, _, err := log.ClaimForHost(ctx, "h-gap", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"gap-fork", "gap-exec", "gap-exit"}, ids(released),
		"once the abandoned lease expires the whole stream is offered again from the oldest, in timestamp order")
}

// The floor is the host's OWN oldest in-flight event, so one host stalled behind a dead claimer must not stall any other host: that
// would turn a bounded per-host wait into a fleet-wide one.
func TestEventLog_InFlightFloorIsPerHost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		ev("stuck-fork", "h-stuck", 100, "fork"),
		ev("stuck-exec", "h-stuck", 200, "exec"),
		ev("other-fork", "h-other", 150, "fork"),
	}))

	stuck, _, err := log.ClaimForHost(ctx, "h-stuck", 1)
	require.NoError(t, err)
	require.Equal(t, []string{"stuck-fork"}, ids(stuck))

	// h-other's event is NEWER than the in-flight one on h-stuck. A floor computed across hosts would swallow it.
	other, _, err := log.ClaimForHost(ctx, "h-other", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"other-fork"}, ids(other), "another host's events are unaffected by this host's in-flight floor")
}

func TestEventLog_ReclaimsStaleClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log, db := newEventLogWithDB(t)

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{ev("e1", "h1", 100, "exec")}))

	claimed, _, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1, "the event is claimed and now in-flight")

	// A fresh claim does not re-offer the in-flight event (its lease has not expired).
	again, _, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	assert.Empty(t, again, "an unexpired in-flight claim is not re-offered")

	// Simulate a worker that crashed between ClaimForHost and Ack: backdate the claim past the lease.
	_, err = db.ExecContext(ctx, "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "e1")
	require.NoError(t, err)

	// The stale claim is now re-offered, so a crashed worker's events are not lost (at-least-once).
	reclaimed, _, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"e1"}, ids(reclaimed), "an expired claim is re-delivered on a later claim")
}

// spec:server-event-ingestion/horizontally-scalable-ingestion-service/two-ingestion-replicas-run-against-the-same-backing-stores
//
// Two EventLog instances over one MySQL event_queue model two ingestion replicas that share only their backing store. Both replicas
// append the same event_id space concurrently; the queue's idempotent INSERT IGNORE (with deadlock retry) must absorb the contention
// so every distinct event is enqueued exactly once and neither replica observes an error caused by the other.
func TestEventLog_ConcurrentReplicasShareOneQueue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testdb.Open(t)
	require.NoError(t, visibilitytestkit.ApplySchema(ctx, db))
	replica := func() visibilityapi.EventLog {
		vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
		require.NoError(t, err)
		return vis.EventLog()
	}
	logA, logB := replica(), replica()

	const distinctEvents = 100
	var errCount atomic.Int64
	appendAll := func(wg *sync.WaitGroup, log visibilityapi.EventLog) {
		defer wg.Done()
		for i := range distinctEvents {
			// Both replicas append the SAME ids, so the dedup is exercised under genuine cross-replica concurrency.
			if err := log.Append(ctx, []visibilityapi.Event{ev(fmt.Sprintf("evt-%03d", i), "h-shared", int64(i+1), "exec")}); err != nil {
				errCount.Add(1)
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go appendAll(&wg, logA)
	go appendAll(&wg, logB)
	wg.Wait()

	require.Zero(t, errCount.Load(), "neither replica observes errors caused by the other")
	pending, err := logA.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(distinctEvents), pending,
		"each event_id is enqueued exactly once despite both replicas appending it concurrently")
}

// spec:server-event-ingestion/decoupled-processing-pipeline/acknowledged-work-is-pruned-from-the-queue
//
// PruneProcessed removes acked rows (processed = 1) so the queue keeps to its in-flight working set, while leaving unprocessed
// (processed = 0) and in-flight (claimed, processed = 2) rows for a later claim.
func TestEventLog_PruneProcessedRemovesOnlyAcked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		ev("acked", "h1", 100, "exec"),
		ev("inflight", "h1", 200, "exec"),
		ev("waiting", "h1", 300, "exec"),
	}))

	// ClaimForHost acked+inflight, ack only "acked", leave "inflight" claimed (processed = 2), "waiting" untouched (processed = 0).
	claimed, stamp, err := log.ClaimForHost(ctx, "h1", 2)
	require.NoError(t, err)
	require.Equal(t, []string{"acked", "inflight"}, ids(claimed))
	// A subset of the claim: acking one of the two rows this claim holds.
	held, err := log.Ack(ctx, []string{"acked"}, stamp)
	require.NoError(t, err)
	require.True(t, held)

	pruned, err := log.PruneProcessed(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pruned, "only the acked row is pruned")

	// The acked row is gone; the in-flight and waiting rows remain (CountPending still counts both not-fully-processed rows).
	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), pending, "in-flight + waiting rows survive the prune")

	// A second prune with nothing acked is a no-op.
	pruned, err = log.PruneProcessed(ctx, 10)
	require.NoError(t, err)
	assert.Zero(t, pruned, "nothing left to prune")
}

// TestEventLog_PruneProcessedBatches drives the batched DELETE loop across more than one batch (batchSize < acked count) and confirms
// every acked row is removed.
func TestEventLog_PruneProcessedBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	const n = 25
	batch := make([]visibilityapi.Event, n)
	allIDs := make([]string, n)
	for i := range batch {
		allIDs[i] = fmt.Sprintf("e-%02d", i)
		batch[i] = ev(allIDs[i], "h1", int64(i+1), "exec")
	}
	require.NoError(t, log.Append(ctx, batch))
	claimed, stamp, err := log.ClaimForHost(ctx, "h1", n)
	require.NoError(t, err)
	require.Len(t, claimed, n)
	held, err := log.Ack(ctx, allIDs, stamp)
	require.NoError(t, err)
	require.True(t, held)

	// batchSize 10 < 25 acked, so the internal loop runs three DELETEs (10, 10, 5) and removes all of them.
	pruned, err := log.PruneProcessed(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(n), pruned, "every acked row is removed across batches")

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Zero(t, pending, "queue is empty after pruning all acked rows")
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/concurrent-workers-within-one-replica-claim-disjoint-event-batches
//
// Issue #544: with intra-replica processor concurrency (#535), many workers claim from event_queue at once. Under the default
// REPEATABLE READ the SKIP LOCKED claim scan takes gap locks on the (processed, host_id, timestamp_ns) index and concurrent
// claimers deadlock on the claim UPDATE (MySQL 1213); a single-box 500-host run logged ~1.6/s. The fix runs the claim at READ
// COMMITTED with a bounded deadlock retry, so concurrent claimers MUST never surface a deadlock AND MUST still partition the queue:
// every seeded event is claimed exactly once. A worker observes an empty claim only once no claimable (processed = 0 or
// lease-expired) rows remain, so breaking on empty drains the whole queue without a spin.
func TestEventLog_ConcurrentClaimersNoDeadlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	const totalEvents = 1500
	const hostCount = 30
	seed := make([]visibilityapi.Event, totalEvents)
	for i := range seed {
		seed[i] = ev(fmt.Sprintf("evt-%04d", i), fmt.Sprintf("h-%02d", i%hostCount), int64(i+1), "exec")
	}
	require.NoError(t, log.Append(ctx, seed))

	const workers = 8
	run := &claimRun{log: log, batch: 50, claimed: make(map[string]int)}
	run.wg.Add(workers)
	for range workers {
		go run.drain(ctx)
	}
	run.wg.Wait()

	require.Zero(t, run.claimErrs.Load(), "concurrent claimers must not surface a deadlock error (#544)")
	require.Zero(t, run.ackErrs.Load(), "acks must not error under concurrency")
	require.Len(t, run.claimed, totalEvents, "every seeded event is claimed exactly once")
	for id, n := range run.claimed {
		assert.Equalf(t, 1, n, "event %s must be claimed by exactly one worker (no double-claim)", id)
	}
}

// claimRun holds the state the concurrent claimers share: claimed counts how many times each event_id was handed out (must end at
// exactly 1), and the atomics tally any claim/ack error. Bundling it lets drain be a low-complexity method rather than a deeply nested
// inline goroutine closure (SonarCloud go:S3776).
type claimRun struct {
	log       visibilityapi.EventLog
	batch     int
	wg        sync.WaitGroup
	mu        sync.Mutex
	claimed   map[string]int
	claimErrs atomic.Int64
	ackErrs   atomic.Int64
	// ackLost counts acks that found the rows no longer in their claim (issue #817). Under a lease long enough to cover this
	// test's work it must stay zero; it is here so a future change that shortens the lease or slows a batch is caught by a
	// number rather than by a doubled counter somewhere downstream.
	ackLost atomic.Int64
}

// drain claims and acks batches until no host has claimable work, recording every claimed event and any error. It walks
// PendingHosts then ClaimForHost, the same two-step the processor uses, so this stays a faithful load test of the claim path.
// PendingHosts excludes rows another worker holds under an unexpired lease, so an empty result means the queue is drained rather
// than momentarily contended, and returning on it cannot spin.
func (r *claimRun) drain(ctx context.Context) {
	defer r.wg.Done()
	for {
		hosts, err := r.log.PendingHosts(ctx, hostCandidatesPerDrain)
		if err != nil {
			r.claimErrs.Add(1)
			return
		}
		if len(hosts) == 0 {
			return // nothing claimable anywhere: every event has already been claimed by some worker
		}
		for _, host := range hosts {
			if !r.claimHost(ctx, host) {
				return
			}
		}
	}
}

// claimHost claims and acks one host's batch, reporting whether the drain should continue. An empty claim is normal: another worker
// took that host between the discovery read and here.
func (r *claimRun) claimHost(ctx context.Context, host string) bool {
	batchEvents, stamp, err := r.log.ClaimForHost(ctx, host, r.batch)
	if err != nil {
		r.claimErrs.Add(1)
		return false
	}
	if len(batchEvents) == 0 {
		return true
	}
	r.mu.Lock()
	for _, e := range batchEvents {
		r.claimed[e.EventID]++
	}
	r.mu.Unlock()
	held, err := r.log.Ack(ctx, ids(batchEvents), stamp)
	if err != nil {
		r.ackErrs.Add(1)
	}
	if !held {
		// Two workers held the same rows and this one lost (issue #817). Counted rather than ignored: before the ack became
		// conditional both would have reported success, which is precisely what made over-lease double processing invisible.
		r.ackLost.Add(1)
	}
	return true
}

// hostCandidatesPerDrain is how many hosts one drain iteration considers, wide enough that eight concurrent workers spread over the
// thirty seeded hosts instead of queueing on the oldest one.
const hostCandidatesPerDrain = 8

func TestEventLog_EmptyOps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	require.NoError(t, log.Append(ctx, nil))
	held, err := log.Ack(ctx, nil, 0)
	require.NoError(t, err)
	assert.True(t, held, "an empty ack is vacuously held")
	setAside, nackErr := log.Nack(ctx, nil)
	require.NoError(t, nackErr)
	assert.Zero(t, setAside, "an empty nack withdraws nothing")

	claimed, _, err := log.ClaimForHost(ctx, "h1", 0)
	require.NoError(t, err)
	assert.Empty(t, claimed)

	noHost, _, err := log.ClaimForHost(ctx, "", 10)
	require.NoError(t, err)
	assert.Empty(t, noHost, "an empty host id claims nothing rather than claiming across hosts")

	hosts, err := log.PendingHosts(ctx, 0)
	require.NoError(t, err)
	assert.Empty(t, hosts)

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pending)
}

// A host blocked behind an unexpired in-flight event has no claimable work, so offering it as a candidate spends a slot in the
// processor's candidate window on a host that must return empty. The window is finite (16 at the default concurrency) and the
// ordering works against us: a blocked host's oldest CLAIMABLE row sits just behind the in-flight one, so it sorts to the front and
// stays there for the whole claim lease. Enough blocked hosts and the window fills with them, turning a bounded per-host pause into
// a fleet-wide one for up to a lease. The hint must therefore apply the same in-flight floor the claim does.
//
// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/a-blocked-host-does-not-occupy-a-candidate-slot
func TestEventLog_PendingHostsSkipsHostsWithNoClaimableWork(t *testing.T) {
	t.Parallel()

	t.Run("a blocked host must not take the slot of a host with work", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		log := newEventLog(t)

		// The blocked host's events are OLDER, so it wins the longest-waiting ordering and takes the single slot on offer.
		require.NoError(t, log.Append(ctx, []visibilityapi.Event{
			ev("blocked-fork", "h-blocked", 100, "fork"),
			ev("blocked-exec", "h-blocked", 200, "exec"),
			ev("ready-fork", "h-ready", 900, "fork"),
		}))

		held, _, err := log.ClaimForHost(ctx, "h-blocked", 1)
		require.NoError(t, err)
		require.Equal(t, []string{"blocked-fork"}, ids(held), "the oldest event goes in flight and stays there")

		hosts, err := log.PendingHosts(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, []string{"h-ready"}, hosts,
			"h-blocked can only return empty until its lease expires, so the one slot must go to the host that has work")
	})

	t.Run("a fleet of blocked hosts must not hide every host with work", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		log := newEventLog(t)

		// A rolling restart strands one in-flight batch per worker per replica. At the default 4 workers a 4-replica deploy strands
		// 16 hosts, exactly the candidate window, so every slot can be blocked at once while the rest of the fleet waits.
		const blocked = 16
		batch := make([]visibilityapi.Event, 0, blocked*2+1)
		for i := range blocked {
			host := fmt.Sprintf("h-stranded-%d", i)
			batch = append(batch,
				ev(fmt.Sprintf("stranded-fork-%d", i), host, int64(100+i), "fork"),
				ev(fmt.Sprintf("stranded-exec-%d", i), host, int64(1000+i), "exec"))
		}
		batch = append(batch, ev("live-fork", "h-live", 5000, "fork"))
		require.NoError(t, log.Append(ctx, batch))

		for i := range blocked {
			held, _, err := log.ClaimForHost(ctx, fmt.Sprintf("h-stranded-%d", i), 1)
			require.NoError(t, err)
			require.Len(t, held, 1, "each stranded host holds one event in flight")
		}

		hosts, err := log.PendingHosts(ctx, blocked)
		require.NoError(t, err)
		assert.Equal(t, []string{"h-live"}, hosts,
			"with every candidate slot claimable by a blocked host, the only host that can be served must still be visible")
	})
}

// TestEventLog_PendingHostsIndexExists pins that the candidate-hint index shipped with the migration corpus rather than only in a
// developer's database. Without it the hint silently reverts to the full scan issue #720 removed: same answers, 20x the cost, and
// nothing fails. A plan assertion would be the more direct test but EXPLAIN output is not stable enough to pin.
func TestEventLog_PendingHostsIndexExists(t *testing.T) {
	t.Parallel()
	_, db := newEventLogWithDB(t)

	var n int
	require.NoError(t, db.GetContext(t.Context(), &n, `
		SELECT COUNT(*) FROM information_schema.statistics
		WHERE table_schema = DATABASE() AND table_name = 'event_queue' AND index_name = 'idx_event_queue_pending'`))
	assert.Positive(t, n, "migration 00003 must have created idx_event_queue_pending")
}

// TestEventLog_PendingHostsBlockedHostWithDeepBacklogDoesNotHideTheFleet is the regression test for a fix that was wrong, kept
// because the wrong version is the tempting one.
//
// While speeding up the hint (issue #720) I tried reading only the oldest N rows per claim state, which measured 20x faster. It is
// broken: the row limit applies BEFORE the in-flight floor is subtracted, so one host with an unexpired in-flight event and N rows
// queued behind it fills the whole window with rows the floor then removes, and the query returns nothing at all while other hosts
// have claimable work. That is the fleet-wide stall #719 exists to prevent.
//
// The existing #719 tests could not catch it: they use a handful of rows per host, so any plausible window swallows them whole. This
// one puts a deep backlog behind the blocked host specifically so a windowed implementation fails here.
func TestEventLog_PendingHostsBlockedHostWithDeepBacklogDoesNotHideTheFleet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	// Comfortably more than any window a future optimization would plausibly pick, and all of it OLDER than h-ready's single event
	// so it sorts first and takes the window.
	const deepBacklog = 2500
	batch := make([]visibilityapi.Event, 0, deepBacklog+2)
	batch = append(batch, ev("blocked-oldest", "h-blocked", 100, "fork"))
	for i := range deepBacklog {
		batch = append(batch, ev(fmt.Sprintf("blocked-%d", i), "h-blocked", int64(101+i), "exec"))
	}
	batch = append(batch, ev("ready-fork", "h-ready", 9_000_000, "fork"))
	require.NoError(t, log.Append(ctx, batch))

	held, _, err := log.ClaimForHost(ctx, "h-blocked", 1)
	require.NoError(t, err)
	require.Equal(t, []string{"blocked-oldest"}, ids(held), "the oldest event goes in flight and blocks everything behind it")

	hosts, err := log.PendingHosts(ctx, 16)
	require.NoError(t, err)
	assert.Equal(t, []string{"h-ready"}, hosts,
		"h-blocked has 2500 queued rows that no claim can return; they must not crowd out the one host that can be served")
}

// spec:server-event-ingestion/acknowledgement-requires-still-holding-the-claim/an-ack-from-a-lost-claim-does-not-acknowledge
// spec:server-event-ingestion/acknowledgement-requires-still-holding-the-claim/an-ack-from-the-holding-claim-acknowledges
//
// TestEventLog_AckRequiresStillHoldingTheClaim covers issue #817, which was a gap in the queue contract rather than in any one
// consumer.
//
// A claim expires after its lease and is re-offered, so an evaluation that outlives its lease runs alongside its own reclaimer.
// Ack was an unconditional UPDATE that ignored its affected-row count, so BOTH attempts acknowledged successfully and neither
// learned it had lost. Alert persistence was unharmed, deduplicating on (source, host, rule, subject), but anything additive done
// after acknowledging counted the batch twice, and anything that came to rely on exactly-once inherited the same gap.
func TestEventLog_AckRequiresStillHoldingTheClaim(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log, db := newEventLogWithDB(t)
	const host = "h-817"

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{ev("e-817", host, 100, "exec")}))

	first, firstStamp, err := log.ClaimForHost(ctx, host, 10)
	require.NoError(t, err)
	require.Len(t, first, 1)

	// Age the claim past its lease, which is what a slow evaluation does to itself, then let a second claimer take the row. This
	// is the over-lease case the lease comment called "well above the longest expected per-batch processing time", which was a
	// design intent with nothing enforcing it.
	_, err = db.ExecContext(ctx, "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "e-817")
	require.NoError(t, err)

	second, secondStamp, err := log.ClaimForHost(ctx, host, 10)
	require.NoError(t, err)
	require.Len(t, second, 1, "an expired claim is re-offered, which is the whole premise")
	require.NotEqual(t, firstStamp, secondStamp, "the re-claim must stamp its own identity, or nothing can tell them apart")

	// Both attempts ack the SAME row, so the cases run in order against one fixture and are deliberately not parallel: the
	// second case's premise is that the first changed nothing. wantPending is what carries that, since a lost ack proves itself
	// by the row still being claimable rather than by its return value alone.
	cases := []struct {
		name        string
		stamp       int64
		wantHeld    bool
		wantPending int64
		why         string
	}{
		{
			name:  "the attempt that lost the claim does not acknowledge",
			stamp: firstStamp, wantHeld: false, wantPending: 1,
			why: "the first attempt must learn it lost, and must leave the row to the claimer that now owns it",
		},
		{
			name:  "the attempt that holds the claim does acknowledge",
			stamp: secondStamp, wantHeld: true, wantPending: 0,
			why: "the holding claim advances the queue",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			held, err := log.Ack(ctx, []string{"e-817"}, tc.stamp)
			require.NoError(t, err, "losing a claim is a normal outcome, not an error")
			assert.Equal(t, tc.wantHeld, held, tc.why)

			pending, err := log.CountPending(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPending, pending, tc.why)
		})
	}
}

// spec:server-event-ingestion/acknowledgement-requires-still-holding-the-claim/an-ack-from-a-lost-claim-does-not-acknowledge
//
// TestEventLog_AckOfAPartlyReclaimedBatchCountsAsLost covers the case my first version of the test above could not: it acked one
// event, so a partial match and a full match were the same thing and treating "any row matched" as held passed.
//
// A batch can be partly reclaimed. The claim's in-flight bound offers rows strictly older than the oldest in-flight one, so an
// expired row at the front of a batch is re-offered while a later row of the SAME batch is still held. Acking the whole batch then
// matches some rows and not others, and the result is used for exactly one thing: deciding whether this attempt processed the batch
// once. It did not, so it must read as lost.
func TestEventLog_AckOfAPartlyReclaimedBatchCountsAsLost(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log, db := newEventLogWithDB(t)
	const host = "h-817-partial"

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		ev("p-first", host, 100, "exec"),
		ev("p-second", host, 200, "exec"),
	}))

	claimed, firstStamp, err := log.ClaimForHost(ctx, host, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 2)

	// Expire only the FIRST row. The second stays in flight under the original claim, and the in-flight floor allows the first to
	// be re-offered because it is strictly older than the oldest in-flight event.
	_, err = db.ExecContext(ctx, "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "p-first")
	require.NoError(t, err)

	reclaimed, secondStamp, err := log.ClaimForHost(ctx, host, 10)
	require.NoError(t, err)
	require.Equal(t, []string{"p-first"}, ids(reclaimed), "only the expired row is re-offered")
	require.NotEqual(t, firstStamp, secondStamp)

	held, err := log.Ack(ctx, []string{"p-first", "p-second"}, firstStamp)
	require.NoError(t, err)
	assert.False(t, held, "one of the two rows belongs to another attempt now, so this attempt did not process the batch")

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), pending, "a partial ack must advance nothing, or the batch is half-acknowledged")
}
