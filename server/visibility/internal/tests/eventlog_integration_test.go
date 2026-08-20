//go:build integration

// Package tests holds per-context integration tests for the visibility bounded context. They skip when EDR_TEST_DSN isn't set,
// matching the project's other DB-using tests, and exercise the EventLog work queue via visibility/bootstrap against a real MySQL.
package tests

import (
	"context"
	"encoding/json"
	"fmt"
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

	claimed, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	require.Len(t, claimed, 2)
	assert.Equal(t, []string{"e1", "e2"}, ids(claimed))
	assert.Equal(t, int64(101), claimed[0].IngestedAtNs, "ingested_at_ns round-trips from the stored row")

	// A re-claim returns nothing: the rows are in-flight (processed = 2), not re-offered.
	again, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	assert.Empty(t, again)

	// Ack one, Nack the other.
	require.NoError(t, log.Ack(ctx, []string{"e1"}))
	require.NoError(t, log.Nack(ctx, []string{"e2"}))

	pending, err = log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pending, "acked event leaves the pending count; nacked event remains")

	// The nacked event is claimable again; the acked one is not.
	reclaimed, err := log.ClaimForHost(ctx, "h1", 10)
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

	claimed, err := log.ClaimForHost(ctx, "h1", 10)
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

	first, err := log.ClaimForHost(ctx, "hostA", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"a1", "a2"}, ids(first), "one host's events, in timestamp order, and no other host's")

	second, err := log.ClaimForHost(ctx, "hostB", 10)
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
	inFlight, err := log.ClaimForHost(ctx, "h-gap", 1)
	require.NoError(t, err)
	require.Equal(t, []string{"gap-fork"}, ids(inFlight), "the oldest event is claimed first")

	// The host still LOOKS pending, because its later events have never been claimed. That is the trap: the hint is honest and the
	// claim is what has to hold the line.
	hosts, err := log.PendingHosts(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"h-gap"}, hosts, "a host with never-claimed events behind an in-flight one is still offered as a hint")

	behind, err := log.ClaimForHost(ctx, "h-gap", 10)
	require.NoError(t, err)
	assert.Empty(t, behind,
		"events behind an unexpired in-flight event must not be claimed: folding gap-exec without gap-fork is the #717 defect")

	// Simulate the holder having died: backdate its claim past the lease. Nothing reclaimed it while the lease was live.
	_, err = db.ExecContext(ctx, "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "gap-fork")
	require.NoError(t, err)

	released, err := log.ClaimForHost(ctx, "h-gap", 10)
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

	stuck, err := log.ClaimForHost(ctx, "h-stuck", 1)
	require.NoError(t, err)
	require.Equal(t, []string{"stuck-fork"}, ids(stuck))

	// h-other's event is NEWER than the in-flight one on h-stuck. A floor computed across hosts would swallow it.
	other, err := log.ClaimForHost(ctx, "h-other", 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"other-fork"}, ids(other), "another host's events are unaffected by this host's in-flight floor")
}

func TestEventLog_ReclaimsStaleClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log, db := newEventLogWithDB(t)

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{ev("e1", "h1", 100, "exec")}))

	claimed, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1, "the event is claimed and now in-flight")

	// A fresh claim does not re-offer the in-flight event (its lease has not expired).
	again, err := log.ClaimForHost(ctx, "h1", 10)
	require.NoError(t, err)
	assert.Empty(t, again, "an unexpired in-flight claim is not re-offered")

	// Simulate a worker that crashed between ClaimForHost and Ack: backdate the claim past the lease.
	_, err = db.ExecContext(ctx, "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "e1")
	require.NoError(t, err)

	// The stale claim is now re-offered, so a crashed worker's events are not lost (at-least-once).
	reclaimed, err := log.ClaimForHost(ctx, "h1", 10)
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
	claimed, err := log.ClaimForHost(ctx, "h1", 2)
	require.NoError(t, err)
	require.Equal(t, []string{"acked", "inflight"}, ids(claimed))
	require.NoError(t, log.Ack(ctx, []string{"acked"}))

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
	claimed, err := log.ClaimForHost(ctx, "h1", n)
	require.NoError(t, err)
	require.Len(t, claimed, n)
	require.NoError(t, log.Ack(ctx, allIDs))

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
	batchEvents, err := r.log.ClaimForHost(ctx, host, r.batch)
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
	if err := r.log.Ack(ctx, ids(batchEvents)); err != nil {
		r.ackErrs.Add(1)
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
	require.NoError(t, log.Ack(ctx, nil))
	require.NoError(t, log.Nack(ctx, nil))

	claimed, err := log.ClaimForHost(ctx, "h1", 0)
	require.NoError(t, err)
	assert.Empty(t, claimed)

	noHost, err := log.ClaimForHost(ctx, "", 10)
	require.NoError(t, err)
	assert.Empty(t, noHost, "an empty host id claims nothing rather than claiming across hosts")

	hosts, err := log.PendingHosts(ctx, 0)
	require.NoError(t, err)
	assert.Empty(t, hosts)

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pending)
}
