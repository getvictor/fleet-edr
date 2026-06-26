//go:build integration

// Package tests holds per-context integration tests for the visibility bounded context. They skip when EDR_TEST_DSN isn't set,
// matching the project's other DB-using tests, and exercise the EventLog work queue via visibility/bootstrap against a real MySQL.
package tests

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
	visibilitytestkit "github.com/fleetdm/edr/server/visibility/testkit"
)

func newEventLog(t *testing.T) visibilityapi.EventLog {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, visibilitytestkit.ApplySchema(t.Context(), db))
	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
	require.NoError(t, err)
	return vis.EventLog()
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
