package commander

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotateServerState models the minimal subset of the command-poll +
// status-update server endpoints the commander hits for a rotate_token
// dispatch: GET /api/commands once (returning the pending rotate_token
// command) then PUT /api/commands/{id} twice (acked + completed). The
// fields capture the status sequence so tests can assert "the
// commander acked then completed" without diving into the HTTP shape.
type rotateServerState struct {
	mu             sync.Mutex
	commandPolled  atomic.Int64
	statusSequence []string
	cmd            command
}

func newRotateServer(t *testing.T, cmd command) (*httptest.Server, *rotateServerState) {
	t.Helper()
	state := &rotateServerState{cmd: cmd}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/commands":
			n := state.commandPolled.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if n > 1 {
				_, _ = w.Write([]byte("[]"))
				return
			}
			_ = json.NewEncoder(w).Encode([]command{state.cmd})
		case r.Method == http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var update statusUpdate
			_ = json.Unmarshal(body, &update)
			state.mu.Lock()
			state.statusSequence = append(state.statusSequence, update.Status)
			state.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, state
}

// Happy path: a pending rotate_token command produces (acked, completed)
// status sequence and the RotateTokenFn closure receives the new token.
func TestExecuteRotateToken_HappyPath(t *testing.T) {
	const newToken = "rotated-token-43-chars-base64url-aaaaaaaaa"
	cmd := command{
		ID:          77,
		HostID:      "host-1",
		CommandType: "rotate_token",
		Payload:     json.RawMessage(`{"new_token":"` + newToken + `"}`),
		Status:      "pending",
	}
	srv, state := newRotateServer(t, cmd)

	var got string
	cmdr := New(Config{
		ServerURL: srv.URL,
		HostID:    "host-1",
		RotateTokenFn: func(_ context.Context, tok string) error {
			got = tok
			return nil
		},
	}, nil, nil)

	cmdr.pollAndDispatch(t.Context())

	assert.Equal(t, newToken, got, "RotateTokenFn must receive the payload's new_token")
	state.mu.Lock()
	defer state.mu.Unlock()
	assert.Equal(t, []string{"acked", "completed"}, state.statusSequence,
		"rotate_token must surface as acked then completed")
}

// A malformed payload (missing new_token) reports the command failed
// without invoking RotateTokenFn. Defensive; a server that ships an
// empty payload is broken, and the agent must not silently accept a
// blank bearer.
func TestExecuteRotateToken_PayloadValidation(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		{"missing field", `{}`, "payload missing new_token"},
		{"empty string", `{"new_token":""}`, "payload missing new_token"},
		{"wrong type for new_token", `{"new_token":123}`, "invalid payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := command{
				ID:          1,
				HostID:      "host-1",
				CommandType: "rotate_token",
				Payload:     json.RawMessage(tc.payload),
				Status:      "pending",
			}
			srv, state := newRotateServer(t, cmd)

			rotateCalled := false
			cmdr := New(Config{
				ServerURL: srv.URL,
				HostID:    "host-1",
				RotateTokenFn: func(context.Context, string) error {
					rotateCalled = true
					return nil
				},
			}, nil, nil)

			cmdr.pollAndDispatch(t.Context())

			assert.False(t, rotateCalled, "RotateTokenFn must not run with a malformed payload")
			state.mu.Lock()
			defer state.mu.Unlock()
			require.Len(t, state.statusSequence, 2)
			assert.Equal(t, "acked", state.statusSequence[0])
			assert.Equal(t, "failed", state.statusSequence[1])
		})
	}
}

// A nil RotateTokenFn surfaces as a "rotate not configured" failure, not
// a panic. Production wires enrollment.TokenProvider.Rotate; tests /
// dry-runs that don't carry a real provider must still receive a clean
// failure response.
func TestExecuteRotateToken_NilFn(t *testing.T) {
	cmd := command{
		ID:          1,
		HostID:      "host-1",
		CommandType: "rotate_token",
		Payload:     json.RawMessage(`{"new_token":"x"}`),
		Status:      "pending",
	}
	srv, state := newRotateServer(t, cmd)

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-1"}, nil, nil)
	cmdr.pollAndDispatch(t.Context())

	state.mu.Lock()
	defer state.mu.Unlock()
	require.Len(t, state.statusSequence, 2)
	assert.Equal(t, "failed", state.statusSequence[1])
}

// RotateTokenFn returning an error (e.g. on-disk write failure) must
// surface as a "failed" status update, not as a silent success that
// claims the rotation applied when in fact it did not. This is the
// integrity property the audit trail relies on.
func TestExecuteRotateToken_FnError(t *testing.T) {
	cmd := command{
		ID:          1,
		HostID:      "host-1",
		CommandType: "rotate_token",
		Payload:     json.RawMessage(`{"new_token":"x"}`),
		Status:      "pending",
	}
	srv, state := newRotateServer(t, cmd)

	cmdr := New(Config{
		ServerURL: srv.URL,
		HostID:    "host-1",
		RotateTokenFn: func(context.Context, string) error {
			return errors.New("simulated disk full")
		},
	}, nil, nil)
	cmdr.pollAndDispatch(t.Context())

	state.mu.Lock()
	defer state.mu.Unlock()
	require.Len(t, state.statusSequence, 2)
	assert.Equal(t, "failed", state.statusSequence[1])
}
