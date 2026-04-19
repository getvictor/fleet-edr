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

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

func setupCommandTestHandler(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, slog.Default())
	return testMux(h), s
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

	withHostA := func(req *http.Request) *http.Request {
		return req.WithContext(authn.WithHostIDForTest(req.Context(), "host-a"))
	}

	t.Run("host-scoped listing", func(t *testing.T) {
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands", nil))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var commands []store.Command
		require.NoError(t, json.NewDecoder(w.Body).Decode(&commands))
		assert.Len(t, commands, 1)
	})

	t.Run("missing host context", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("status filter", func(t *testing.T) {
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands?status=pending", nil))
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

	withHostA := func(req *http.Request) *http.Request {
		return req.WithContext(authn.WithHostIDForTest(req.Context(), "host-a"))
	}

	t.Run("ack", func(t *testing.T) {
		body := `{"status":"acked"}`
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", id), strings.NewReader(body)))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)

		got, err := s.GetCommand(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "acked", got.Status)
	})

	t.Run("complete with result", func(t *testing.T) {
		body := `{"status":"completed","result":{"killed":true}}`
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", id), strings.NewReader(body)))
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
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", id), strings.NewReader(body)))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("not found", func(t *testing.T) {
		body := `{"status":"acked"}`
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "PUT", "/api/v1/commands/99999", strings.NewReader(body)))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("missing host context", func(t *testing.T) {
		body := `{"status":"acked"}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", id), strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// TestHostScopedCommandAccess exercises the host-token path: an agent authenticated as host A
// must only see + modify its own commands, even if it passes another host's id in the query.
// This is the regression test for the Phase 1 QA bug where GET /api/v1/commands was registered
// under admin auth, locking out the commander entirely.
func TestHostScopedCommandAccess(t *testing.T) {
	mux, s := setupCommandTestHandler(t)
	ctx := t.Context()

	hostA := "11111111-1111-1111-1111-111111111111"
	hostB := "22222222-2222-2222-2222-222222222222"

	cmdA, err := s.InsertCommand(ctx, store.Command{HostID: hostA, CommandType: "kill_process", Payload: json.RawMessage(`{}`)})
	require.NoError(t, err)
	cmdB, err := s.InsertCommand(ctx, store.Command{HostID: hostB, CommandType: "kill_process", Payload: json.RawMessage(`{}`)})
	require.NoError(t, err)

	withHostA := func(req *http.Request) *http.Request {
		return req.WithContext(authn.WithHostIDForTest(req.Context(), hostA))
	}

	t.Run("GET scoped to authenticated host", func(t *testing.T) {
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands", nil))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var got []store.Command
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		assert.Len(t, got, 1)
		assert.Equal(t, hostA, got[0].HostID)
	})

	t.Run("GET ignores host_id query when host-token authed", func(t *testing.T) {
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/commands?host_id="+hostB, nil))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var got []store.Command
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		assert.Len(t, got, 1)
		assert.Equal(t, hostA, got[0].HostID, "agent A must not see host B's commands via query spoofing")
	})

	t.Run("PUT on foreign command returns 404", func(t *testing.T) {
		body := `{"status":"acked"}`
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", cmdB), strings.NewReader(body)))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)

		// Cross-check the command wasn't actually updated.
		got, err := s.GetCommand(ctx, cmdB)
		require.NoError(t, err)
		assert.Equal(t, "pending", got.Status)
	})

	t.Run("PUT on own command succeeds", func(t *testing.T) {
		body := `{"status":"completed","result":{"ok":true}}`
		req := withHostA(httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/commands/%d", cmdA), strings.NewReader(body)))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}
