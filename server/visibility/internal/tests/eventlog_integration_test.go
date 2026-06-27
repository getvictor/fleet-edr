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

	claimed, err := log.Claim(ctx, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 2)
	assert.Equal(t, []string{"e1", "e2"}, ids(claimed))
	assert.Equal(t, int64(101), claimed[0].IngestedAtNs, "ingested_at_ns round-trips from the stored row")

	// A re-claim returns nothing: the rows are in-flight (processed = 2), not re-offered.
	again, err := log.Claim(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, again)

	// Ack one, Nack the other.
	require.NoError(t, log.Ack(ctx, []string{"e1"}))
	require.NoError(t, log.Nack(ctx, []string{"e2"}))

	pending, err = log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pending, "acked event leaves the pending count; nacked event remains")

	// The nacked event is claimable again; the acked one is not.
	reclaimed, err := log.Claim(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"e2"}, ids(reclaimed))
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

func TestEventLog_ClaimOrderingAndDisjoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	// Interleave two hosts; the claim orders host-major then timestamp, and successive claims are disjoint.
	require.NoError(t, log.Append(ctx, []visibilityapi.Event{
		ev("b2", "hostB", 400, "exec"),
		ev("a1", "hostA", 100, "exec"),
		ev("b1", "hostB", 200, "exec"),
		ev("a2", "hostA", 300, "exec"),
	}))

	first, err := log.Claim(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"a1", "a2"}, ids(first), "ordered by (host_id, timestamp_ns)")

	second, err := log.Claim(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"b1", "b2"}, ids(second), "second claim is disjoint from the first")
}

func TestEventLog_ReclaimsStaleClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log, db := newEventLogWithDB(t)

	require.NoError(t, log.Append(ctx, []visibilityapi.Event{ev("e1", "h1", 100, "exec")}))

	claimed, err := log.Claim(ctx, 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1, "the event is claimed and now in-flight")

	// A fresh claim does not re-offer the in-flight event (its lease has not expired).
	again, err := log.Claim(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, again, "an unexpired in-flight claim is not re-offered")

	// Simulate a worker that crashed between Claim and Ack: backdate the claim past the lease.
	_, err = db.ExecContext(ctx, "UPDATE event_queue SET claimed_at_ns = 1 WHERE event_id = ?", "e1")
	require.NoError(t, err)

	// The stale claim is now re-offered, so a crashed worker's events are not lost (at-least-once).
	reclaimed, err := log.Claim(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"e1"}, ids(reclaimed), "an expired claim is re-delivered on a later Claim")
}

// spec:server-event-ingestion/horizontally-scalable-ingestion-service/two-ingestion-replicas-run-against-the-same-database
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

func TestEventLog_EmptyOps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := newEventLog(t)

	require.NoError(t, log.Append(ctx, nil))
	require.NoError(t, log.Ack(ctx, nil))
	require.NoError(t, log.Nack(ctx, nil))

	claimed, err := log.Claim(ctx, 0)
	require.NoError(t, err)
	assert.Empty(t, claimed)

	pending, err := log.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pending)
}
