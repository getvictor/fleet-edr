package store

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInsertAndGetCommand(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	payload := json.RawMessage(`{"pid":1234,"path":"/tmp/payload"}`)
	id, err := s.InsertCommand(ctx, Command{
		HostID:      "host-a",
		CommandType: "kill_process",
		Payload:     payload,
	})
	require.NoError(t, err)
	assert.Positive(t, id)

	got, err := s.GetCommand(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "host-a", got.HostID)
	assert.Equal(t, "kill_process", got.CommandType)
	assert.Equal(t, "pending", got.Status)
	assert.JSONEq(t, `{"pid":1234,"path":"/tmp/payload"}`, string(got.Payload))
	assert.Nil(t, got.AckedAt)
	assert.Nil(t, got.CompletedAt)
}

func TestListCommands(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	_, err := s.InsertCommand(ctx, Command{HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{}`)})
	require.NoError(t, err)
	_, err = s.InsertCommand(ctx, Command{HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{}`)})
	require.NoError(t, err)
	_, err = s.InsertCommand(ctx, Command{HostID: "host-b", CommandType: "kill_process", Payload: json.RawMessage(`{}`)})
	require.NoError(t, err)

	t.Run("filter by host", func(t *testing.T) {
		commands, err := s.ListCommands(ctx, "host-a", "")
		require.NoError(t, err)
		assert.Len(t, commands, 2)
	})

	t.Run("filter by status", func(t *testing.T) {
		commands, err := s.ListCommands(ctx, "host-a", "pending")
		require.NoError(t, err)
		assert.Len(t, commands, 2)

		commands, err = s.ListCommands(ctx, "host-a", "completed")
		require.NoError(t, err)
		assert.Empty(t, commands)
	})

	t.Run("different host", func(t *testing.T) {
		commands, err := s.ListCommands(ctx, "host-b", "")
		require.NoError(t, err)
		assert.Len(t, commands, 1)
	})
}

func TestUpdateCommandStatus(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	id, err := s.InsertCommand(ctx, Command{HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1}`)})
	require.NoError(t, err)

	t.Run("ack sets acked_at", func(t *testing.T) {
		err := s.UpdateCommandStatus(ctx, id, "acked", nil)
		require.NoError(t, err)

		got, err := s.GetCommand(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "acked", got.Status)
		assert.NotNil(t, got.AckedAt)
		assert.Nil(t, got.CompletedAt)
	})

	t.Run("complete sets completed_at and result", func(t *testing.T) {
		result := json.RawMessage(`{"killed":true}`)
		err := s.UpdateCommandStatus(ctx, id, "completed", result)
		require.NoError(t, err)

		got, err := s.GetCommand(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "completed", got.Status)
		assert.NotNil(t, got.CompletedAt)
		assert.JSONEq(t, `{"killed":true}`, string(got.Result))
	})
}

func TestUpdateCommandStatusNotFound(t *testing.T) {
	s := OpenTestStore(t)
	err := s.UpdateCommandStatus(t.Context(), 99999, "acked", nil)
	assert.Error(t, err)
}

func TestGetCommandNotFound(t *testing.T) {
	s := OpenTestStore(t)
	got, err := s.GetCommand(t.Context(), 99999)
	require.NoError(t, err)
	assert.Nil(t, got)
}
