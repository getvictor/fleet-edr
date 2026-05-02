package mysql

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	srvbootstrap "github.com/fleetdm/edr/server/bootstrap"
	"github.com/fleetdm/edr/server/response/api"
)

// commandsDDLForTests duplicates the CREATE TABLE statement from
// server/response/bootstrap/schema.go. Authoritative copy lives there;
// these unit tests run below the bootstrap layer that would normally
// apply it. Keep in lockstep with bootstrap/schema.go.
const commandsDDLForTests = `CREATE TABLE IF NOT EXISTS commands (
	id           BIGINT AUTO_INCREMENT PRIMARY KEY,
	host_id      VARCHAR(255)  NOT NULL,
	command_type VARCHAR(64)   NOT NULL,
	payload      JSON          NOT NULL,
	status       ENUM('pending', 'acked', 'completed', 'failed') NOT NULL DEFAULT 'pending',
	created_at   TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	acked_at     TIMESTAMP(6)  NULL,
	completed_at TIMESTAMP(6)  NULL,
	result       JSON,
	INDEX idx_commands_host_status (host_id, status),
	INDEX idx_commands_created (created_at)
)`

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := srvbootstrap.OpenTestDB(t)
	if _, err := s.ExecContext(t.Context(), commandsDDLForTests); err != nil {
		t.Fatalf("apply commands schema: %v", err)
	}
	return NewStore(s)
}

func TestInsertAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	payload := json.RawMessage(`{"pid":1234,"path":"/tmp/payload"}`)
	id, err := s.Insert(ctx, "host-a", "kill_process", payload)
	require.NoError(t, err)
	assert.Positive(t, id)

	got, err := s.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "host-a", got.HostID)
	assert.Equal(t, "kill_process", got.CommandType)
	assert.Equal(t, api.StatusPending, got.Status)
	assert.JSONEq(t, `{"pid":1234,"path":"/tmp/payload"}`, string(got.Payload))
	assert.Nil(t, got.AckedAt)
	assert.Nil(t, got.CompletedAt)
}

func TestListForHost(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	_, err := s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "host-b", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	t.Run("filter by host", func(t *testing.T) {
		commands, err := s.ListForHost(ctx, "host-a", "")
		require.NoError(t, err)
		assert.Len(t, commands, 2)
	})

	t.Run("filter by status", func(t *testing.T) {
		commands, err := s.ListForHost(ctx, "host-a", "pending")
		require.NoError(t, err)
		assert.Len(t, commands, 2)

		commands, err = s.ListForHost(ctx, "host-a", "completed")
		require.NoError(t, err)
		assert.Empty(t, commands)
	})

	t.Run("different host", func(t *testing.T) {
		commands, err := s.ListForHost(ctx, "host-b", "")
		require.NoError(t, err)
		assert.Len(t, commands, 1)
	})
}

func TestUpdateStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	id, err := s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{"pid":1}`))
	require.NoError(t, err)

	t.Run("ack sets acked_at", func(t *testing.T) {
		err := s.UpdateStatus(ctx, id, "host-a", api.StatusPending, api.StatusAcked, nil)
		require.NoError(t, err)

		got, err := s.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, api.StatusAcked, got.Status)
		assert.NotNil(t, got.AckedAt)
		assert.Nil(t, got.CompletedAt)
	})

	t.Run("complete sets completed_at and result", func(t *testing.T) {
		result := json.RawMessage(`{"killed":true}`)
		err := s.UpdateStatus(ctx, id, "host-a", api.StatusAcked, api.StatusCompleted, result)
		require.NoError(t, err)

		got, err := s.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, api.StatusCompleted, got.Status)
		assert.NotNil(t, got.CompletedAt)
		assert.JSONEq(t, `{"killed":true}`, string(got.Result))
	})
}

// TestUpdateStatusForeignHostRejected covers defence-in-depth on the
// (id, host_id) WHERE clause: host-b cannot ack a command queued for
// host-a, even via a hand-crafted id. The store collapses "wrong host"
// + "unknown id" to the same ErrCommandNotFound so a malicious agent
// can't probe other hosts' command_ids.
func TestUpdateStatusForeignHostRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	id, err := s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	err = s.UpdateStatus(ctx, id, "host-b", api.StatusPending, api.StatusAcked, nil)
	require.ErrorIs(t, err, api.ErrCommandNotFound)

	// Original row untouched.
	got, err := s.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusPending, got.Status)
	assert.Nil(t, got.AckedAt)
}

func TestUpdateStatusNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.UpdateStatus(t.Context(), 99999, "host-a", api.StatusPending, api.StatusAcked, nil)
	require.ErrorIs(t, err, api.ErrCommandNotFound)
}

// TestUpdateStatusInvalidTarget covers the store-layer reject of a
// non-terminal status (or a typo). Passing api.StatusPending here is
// rejected with ErrInvalidStatusTransition so a buggy caller can't
// reset an in-flight command to pending.
func TestUpdateStatusInvalidTarget(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	id, err := s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	err = s.UpdateStatus(ctx, id, "host-a", api.StatusPending, api.StatusPending, nil)
	require.ErrorIs(t, err, api.ErrInvalidStatusTransition)
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(t.Context(), 99999)
	require.ErrorIs(t, err, api.ErrCommandNotFound)
}

// TestUpdateStatusRaceLost simulates the TOCTOU window: caller A's
// expected-from is stale because caller B already advanced the row.
// The store must reject A's UPDATE with ErrInvalidStatusTransition
// (not silently overwrite the newer state).
func TestUpdateStatusRaceLost(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	id, err := s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	// Caller B wins: pending -> acked.
	require.NoError(t, s.UpdateStatus(ctx, id, "host-a", api.StatusPending, api.StatusAcked, nil))

	// Caller A's stale read still says pending. Their UPDATE must
	// fail with ErrInvalidStatusTransition; the row must keep the
	// acked state from caller B.
	err = s.UpdateStatus(ctx, id, "host-a", api.StatusPending, api.StatusAcked, nil)
	require.ErrorIs(t, err, api.ErrInvalidStatusTransition)

	got, err := s.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusAcked, got.Status)
}

func TestCountPending(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	count, err := s.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	for range 3 {
		_, err := s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
		require.NoError(t, err)
	}
	count, err = s.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Acked / completed don't count.
	id, err := s.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)
	require.NoError(t, s.UpdateStatus(ctx, id, "host-a", api.StatusPending, api.StatusAcked, nil))
	count, err = s.CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}
