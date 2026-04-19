package commander

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchPending(t *testing.T) {
	commands := []command{
		{ID: 1, HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{"pid":123}`), Status: "pending"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/commands", r.URL.Path)
		assert.Equal(t, "host-a", r.URL.Query().Get("host_id"))
		assert.Equal(t, "pending", r.URL.Query().Get("status"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(commands)
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	result, err := cmdr.fetchPending(t.Context())
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, int64(1), result[0].ID)
	assert.Equal(t, "kill_process", result[0].CommandType)
}

func TestFetchPendingWithAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", TokenFn: func() string { return "test-key" }}, nil, nil)
	result, err := cmdr.fetchPending(t.Context())
	require.NoError(t, err)
	assert.Empty(t, result)
}

// TestFetchPending401_CallsOnAuthFail locks in the contract that a 401 from the server wakes
// up the enrollment re-auth hook. Regression bar for the Phase 1 QA bug where a revoked token
// left the commander silently stuck.
func TestFetchPending401_CallsOnAuthFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer srv.Close()

	var called atomic.Int64
	cmdr := New(Config{
		ServerURL:  srv.URL,
		HostID:     "host-a",
		TokenFn:    func() string { return "stale-token" },
		OnAuthFail: func(context.Context) { called.Add(1) },
	}, nil, nil)

	_, err := cmdr.fetchPending(t.Context())
	require.Error(t, err)
	assert.Equal(t, int64(1), called.Load(), "401 on fetchPending must trigger OnAuthFail exactly once")
}

// TestUpdateStatus401_CallsOnAuthFail covers the PUT /commands/{id} path — a token can be
// revoked between fetchPending and the following ack/complete, and the hook must fire there
// too or recovery waits for the next poll tick.
func TestUpdateStatus401_CallsOnAuthFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var called atomic.Int64
	cmdr := New(Config{
		ServerURL:  srv.URL,
		HostID:     "host-a",
		TokenFn:    func() string { return "stale-token" },
		OnAuthFail: func(context.Context) { called.Add(1) },
	}, nil, nil)

	err := cmdr.updateStatus(t.Context(), 42, "acked", nil)
	require.Error(t, err)
	assert.Equal(t, int64(1), called.Load(), "401 on updateStatus must trigger OnAuthFail exactly once")
}

func TestDispatchUnknownCommand(t *testing.T) {
	var mu sync.Mutex
	var updates []statusUpdate

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var u statusUpdate
			_ = json.NewDecoder(r.Body).Decode(&u)
			mu.Lock()
			updates = append(updates, u)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	cmd := command{ID: 42, CommandType: "reboot", Payload: json.RawMessage(`{}`)}
	cmdr.dispatch(t.Context(), cmd)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, updates, 2)
	assert.Equal(t, "acked", updates[0].Status)
	assert.Equal(t, "failed", updates[1].Status)
	assert.Contains(t, string(updates[1].Result), "unknown command type")
}

func TestDispatchKillInvalidPayload(t *testing.T) {
	var mu sync.Mutex
	var updates []statusUpdate

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var u statusUpdate
			_ = json.NewDecoder(r.Body).Decode(&u)
			mu.Lock()
			updates = append(updates, u)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	cmd := command{ID: 43, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":0}`)}
	cmdr.dispatch(t.Context(), cmd)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, updates, 2)
	assert.Equal(t, "acked", updates[0].Status)
	assert.Equal(t, "failed", updates[1].Status)
	assert.Contains(t, string(updates[1].Result), "invalid pid")
}

func TestRunPolls(t *testing.T) {
	var callCount int
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Interval: 50 * time.Millisecond}, nil, nil)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	_ = cmdr.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	assert.GreaterOrEqual(t, callCount, 2, "should have polled at least twice")
}
