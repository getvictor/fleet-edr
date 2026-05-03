// Per-context integration tests for the response bounded context.
// Exercise the full bootstrap.New -> ApplySchema -> Service stack
// against a real MySQL. Skips when EDR_TEST_DSN isn't set, matching
// the project's other DB-using test files.
//
// Per docs/adr/0004-modular-monolith-bounded-contexts.md.

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	srvbootstrap "github.com/fleetdm/edr/server/bootstrap"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/bootstrap"
)

// recordingHeartbeat captures every Heartbeat invocation so tests
// can assert the per-poll last-seen bump fires (and only fires when
// the closure is wired).
type recordingHeartbeat struct {
	mu    sync.Mutex
	calls []heartbeatCall
}

type heartbeatCall struct {
	HostID string
	At     time.Time
}

func (r *recordingHeartbeat) Bump(_ context.Context, hostID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, heartbeatCall{HostID: hostID, At: at})
	return nil
}

func (r *recordingHeartbeat) snapshot() []heartbeatCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]heartbeatCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// newResponse wires response.bootstrap.New against a fresh test DB.
// Heartbeat is the recording closure (or nil if the test passes nil).
func newResponse(t *testing.T, hb *recordingHeartbeat) *bootstrap.Response {
	t.Helper()
	s := srvbootstrap.OpenTestDB(t)
	deps := bootstrap.Deps{
		DB: s,
	}
	if hb != nil {
		deps.Heartbeat = hb.Bump
	}
	r, err := bootstrap.New(deps)
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r
}

// TestInsert_HappyPath inserts a command and confirms it round-trips
// through Get with the expected fields populated.
func TestInsert_HappyPath(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	id, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{"pid":1234}`))
	require.NoError(t, err)
	assert.Positive(t, id)

	cmd, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "host-a", cmd.HostID)
	assert.Equal(t, "kill_process", cmd.CommandType)
	assert.Equal(t, api.StatusPending, cmd.Status)
	assert.JSONEq(t, `{"pid":1234}`, string(cmd.Payload))
}

// TestInsert_ValidationErrors covers each branch of the
// service-level validation. Empty strings + zero-byte payload all
// wrap api.ErrInvalidInsertRequest.
func TestInsert_ValidationErrors(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	cases := []struct {
		name        string
		hostID      string
		commandType string
		payload     []byte
	}{
		{"empty hostID", "", "kill_process", []byte("{}")},
		{"empty commandType", "host-a", "", []byte("{}")},
		{"empty payload", "host-a", "kill_process", nil},
		{"whitespace hostID", "   ", "kill_process", []byte("{}")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Service().Insert(ctx, tc.hostID, tc.commandType, tc.payload)
			require.ErrorIs(t, err, api.ErrInvalidInsertRequest)
		})
	}
}

// TestListForHost_FiltersByStatus locks the (host_id, status) filter.
func TestListForHost_FiltersByStatus(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	for range 3 {
		_, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
		require.NoError(t, err)
	}
	_, err := r.Service().Insert(ctx, "host-b", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	pending, err := r.Service().ListForHost(ctx, "host-a", api.StatusPending)
	require.NoError(t, err)
	assert.Len(t, pending, 3)

	completed, err := r.Service().ListForHost(ctx, "host-a", api.StatusCompleted)
	require.NoError(t, err)
	assert.Empty(t, completed)

	all, err := r.Service().ListForHost(ctx, "host-a", "")
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

// TestListForHost_TriggersHeartbeat asserts the per-poll last-seen
// side effect fires for the right host. Skipping this regression
// would silently break the UI's "Online / Offline" pill on every
// poll.
func TestListForHost_TriggersHeartbeat(t *testing.T) {
	hb := &recordingHeartbeat{}
	r := newResponse(t, hb)
	ctx := t.Context()

	_, err := r.Service().ListForHost(ctx, "host-a", "")
	require.NoError(t, err)

	calls := hb.snapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, "host-a", calls[0].HostID)
	assert.WithinDuration(t, time.Now(), calls[0].At, 5*time.Second)
}

// TestListForHost_HeartbeatErrorIsNonFatal uses a closure that
// always returns an error and confirms ListForHost still returns
// the (empty) command slice. The poll must NOT fail because the
// hosts table hiccupped -- the agent already got its commands.
func TestListForHost_HeartbeatErrorIsNonFatal(t *testing.T) {
	r := newResponseWithHeartbeat(t, func(context.Context, string, time.Time) error {
		return errors.New("hosts table down")
	})
	ctx := t.Context()

	commands, err := r.Service().ListForHost(ctx, "host-a", "")
	require.NoError(t, err)
	assert.NotNil(t, commands)
}

func newResponseWithHeartbeat(t *testing.T, hb bootstrap.Heartbeat) *bootstrap.Response {
	t.Helper()
	s := srvbootstrap.OpenTestDB(t)
	r, err := bootstrap.New(bootstrap.Deps{
		DB:        s,
		Heartbeat: hb,
	})
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r
}

// TestUpdateStatus_LifecycleHappyPath walks pending -> acked ->
// completed end-to-end through the public Service surface.
func TestUpdateStatus_LifecycleHappyPath(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	id, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{"pid":1}`))
	require.NoError(t, err)

	require.NoError(t, r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{
		HostID: "host-a",
		ID:     id,
		Status: api.StatusAcked,
	}))
	got, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusAcked, got.Status)
	require.NotNil(t, got.AckedAt)

	require.NoError(t, r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{
		HostID: "host-a",
		ID:     id,
		Status: api.StatusCompleted,
		Result: json.RawMessage(`{"killed":true}`),
	}))
	got, err = r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusCompleted, got.Status)
	require.NotNil(t, got.CompletedAt)
	assert.JSONEq(t, `{"killed":true}`, string(got.Result))
}

// TestUpdateStatus_RejectsForbiddenTransitions covers two key
// invariants: pending -> completed (must ack first) and a terminal
// state being immutable.
func TestUpdateStatus_RejectsForbiddenTransitions(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	id, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	t.Run("pending->completed must ack first", func(t *testing.T) {
		err := r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{
			HostID: "host-a", ID: id, Status: api.StatusCompleted,
		})
		require.ErrorIs(t, err, api.ErrInvalidStatusTransition)
	})

	// Walk it forward to acked then completed for the next subtest.
	require.NoError(t, r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{
		HostID: "host-a", ID: id, Status: api.StatusAcked,
	}))
	require.NoError(t, r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{
		HostID: "host-a", ID: id, Status: api.StatusCompleted,
		Result: json.RawMessage(`{}`),
	}))

	t.Run("completed terminal", func(t *testing.T) {
		err := r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{
			HostID: "host-a", ID: id, Status: api.StatusFailed,
		})
		require.ErrorIs(t, err, api.ErrInvalidStatusTransition)
	})
}

// TestUpdateStatus_ForeignHostRejected: host-b cannot ack host-a's
// command. The collapse to ErrCommandNotFound (not a distinct
// "wrong host" error) defends against probing for other hosts'
// command_ids.
func TestUpdateStatus_ForeignHostRejected(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	id, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	err = r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{
		HostID: "host-b",
		ID:     id,
		Status: api.StatusAcked,
	})
	require.ErrorIs(t, err, api.ErrCommandNotFound)

	got, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusPending, got.Status, "host-a's row must be untouched")
}

// TestAgentRoutes_HostTokenScoped wires the agent handler behind a
// fake host-token middleware and confirms a token for host-a sees
// only host-a's commands -- ?host_id=host-b query spoofing is
// ignored. Inherits the phase-1 TestHostScopedCommandAccess
// regression coverage.
func TestAgentRoutes_HostTokenScoped(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	_, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)
	idB, err := r.Service().Insert(ctx, "host-b", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)

	mux := http.NewServeMux()
	r.RegisterAgentRoutes(mux)
	srv := httptest.NewServer(withHostID(mux, "host-a"))
	t.Cleanup(srv.Close)

	t.Run("GET ignores host_id query when host-token authed", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/commands?host_id=host-b", nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var got []api.Command
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		require.Len(t, got, 1)
		assert.Equal(t, "host-a", got[0].HostID)
	})

	t.Run("PUT on foreign command returns 404", func(t *testing.T) {
		body := strings.NewReader(`{"status":"acked"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut,
			srv.URL+"/api/commands/"+intStr(idB), body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		// Untouched
		got, err := r.Service().Get(ctx, idB)
		require.NoError(t, err)
		assert.Equal(t, api.StatusPending, got.Status)
	})
}

// TestOperatorRoutes_PostAndGet covers the session-gated surface.
// Tests don't wrap in real session+CSRF middleware -- those are
// owned by identity and tested there. Here we just confirm the
// routes are wired and the bodies + audit payloads match.
func TestOperatorRoutes_PostAndGet(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	mux := http.NewServeMux()
	r.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Run("POST creates command", func(t *testing.T) {
		body := strings.NewReader(`{"host_id":"host-a","command_type":"kill_process","payload":{"pid":99}}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/commands", body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		var got map[string]int64
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Positive(t, got["id"])
	})

	t.Run("POST rejects empty fields", func(t *testing.T) {
		body := strings.NewReader(`{"host_id":"","command_type":"kill_process","payload":{}}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/commands", body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("GET returns command", func(t *testing.T) {
		// Insert via service for a stable id.
		id, err := r.Service().Insert(ctx, "host-c", "kill_process", json.RawMessage(`{"pid":7}`))
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/commands/"+intStr(id), nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var got api.Command
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, id, got.ID)
		assert.Equal(t, "host-c", got.HostID)
	})

	t.Run("GET on missing id returns 404", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/commands/99999", nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// TestCountPending counts only pending rows (not acked / completed).
func TestCountPending(t *testing.T) {
	r := newResponse(t, nil)
	ctx := t.Context()

	for range 3 {
		_, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
		require.NoError(t, err)
	}
	count, err := r.Service().CountPending(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

// TestBootstrap_MissingDB surfaces the required-field error.
func TestBootstrap_MissingDB(t *testing.T) {
	_, err := bootstrap.New(bootstrap.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB")
}

// withHostID wraps mux in a tiny middleware that pins host_id on
// the request context the way the real endpoint.HostToken middleware
// does. Lets the agent handler tests run without spinning up
// endpoint bootstrap + a token mint.
func withHostID(next http.Handler, hostID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := endpointapi.WithHostIDForTest(r.Context(), hostID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func intStr(n int64) string { return strconv.FormatInt(n, 10) }
