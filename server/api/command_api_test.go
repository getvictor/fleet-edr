package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

func setupCommandTestHandler(t *testing.T) (*http.ServeMux, *store.Store) {
	t.Helper()
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, "", slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, s
}

func TestCreateCommand(t *testing.T) {
	mux, s := setupCommandTestHandler(t)
	ctx := t.Context()

	body := `{"host_id":"host-a","command_type":"kill_process","payload":{"pid":1234,"path":"/tmp/payload"}}`
	req := httptest.NewRequestWithContext(ctx, "POST", "/api/v1/commands", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]int64
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Positive(t, resp["id"])

	got, err := s.GetCommand(ctx, resp["id"])
	require.NoError(t, err)
	assert.Equal(t, "kill_process", got.CommandType)
	assert.Equal(t, "pending", got.Status)
}

func TestCreateCommandValidation(t *testing.T) {
	mux, _ := setupCommandTestHandler(t)

	t.Run("missing host_id", func(t *testing.T) {
		body := `{"command_type":"kill_process","payload":{}}`
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/commands", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing command_type", func(t *testing.T) {
		body := `{"host_id":"host-a","payload":{}}`
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/commands", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestListCommandsAPI(t *testing.T) {
	mux, s := setupCommandTestHandler(t)
	ctx := t.Context()

	_, err := s.InsertCommand(ctx, store.Command{HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{}`)})
	require.NoError(t, err)

	t.Run("with host_id", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands?host_id=host-a", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var commands []store.Command
		require.NoError(t, json.NewDecoder(w.Body).Decode(&commands))
		assert.Len(t, commands, 1)
	})

	t.Run("missing host_id", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("with status filter", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands?host_id=host-a&status=pending", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var commands []store.Command
		require.NoError(t, json.NewDecoder(w.Body).Decode(&commands))
		assert.Len(t, commands, 1)
	})
}

func TestUpdateCommandStatusAPI(t *testing.T) {
	mux, s := setupCommandTestHandler(t)
	ctx := t.Context()

	id, err := s.InsertCommand(ctx, store.Command{HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1}`)})
	require.NoError(t, err)

	t.Run("ack", func(t *testing.T) {
		body := `{"status":"acked"}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", id), strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)

		got, err := s.GetCommand(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "acked", got.Status)
	})

	t.Run("complete with result", func(t *testing.T) {
		body := `{"status":"completed","result":{"killed":true}}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", id), strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)

		got, err := s.GetCommand(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "completed", got.Status)
		assert.JSONEq(t, `{"killed":true}`, string(got.Result))
	})

	t.Run("invalid status", func(t *testing.T) {
		body := `{"status":"pending"}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", id), strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("not found", func(t *testing.T) {
		body := `{"status":"acked"}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", "/api/v1/commands/99999", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
