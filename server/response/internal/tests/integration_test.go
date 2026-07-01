//go:build integration

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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/fleetdm/edr/internal/control"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// allowAllAuthZ stubs identityapi.AuthZ as an unconditional grant for the response-context integration tests. Per-action role coverage
// lives in server/identity/internal/authz/engine_test.go.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

// recordingHeartbeat captures every Heartbeat invocation so tests can assert the per-poll last-seen bump fires (and only fires when
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
	s := full.Open(t)
	deps := bootstrap.Deps{
		DB:    s,
		AuthZ: allowAllAuthZ{},
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
	t.Parallel()
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

// TestInsert_ValidationErrors covers each branch of the service-level validation. Empty strings + zero-byte payload all wrap
// api.ErrInvalidInsertRequest.
func TestInsert_ValidationErrors(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// TestListForHost_TriggersHeartbeat asserts the per-poll last-seen side effect fires for the right host. Skipping this regression
// would silently break the UI's "Online / Offline" pill on every poll.
func TestListForHost_TriggersHeartbeat(t *testing.T) {
	t.Parallel()
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

// TestListForHost_HeartbeatErrorIsNonFatal uses a closure that always returns an error and confirms ListForHost still returns the
// (empty) command slice. The poll must NOT fail because the hosts table hiccupped: the agent already got its commands.
func TestListForHost_HeartbeatErrorIsNonFatal(t *testing.T) {
	t.Parallel()
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
	s := full.Open(t)
	r, err := bootstrap.New(bootstrap.Deps{
		DB:        s,
		Heartbeat: hb,
		AuthZ:     allowAllAuthZ{},
	})
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r
}

// TestUpdateStatus_LifecycleHappyPath walks pending -> acked ->
// completed end-to-end through the public Service surface.
func TestUpdateStatus_LifecycleHappyPath(t *testing.T) {
	t.Parallel()
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

// TestUpdateStatus_RejectsForbiddenTransitions covers two key invariants: pending -> completed (must ack first) and a terminal state
// being immutable.
func TestUpdateStatus_RejectsForbiddenTransitions(t *testing.T) {
	t.Parallel()
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

// TestUpdateStatus_ForeignHostRejected: host-b cannot ack host-a's command. The collapse to ErrCommandNotFound (not a distinct "wrong
// host" error) defends against probing for other hosts' command_ids.
func TestUpdateStatus_ForeignHostRejected(t *testing.T) {
	t.Parallel()
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

// TestAgentRoutes_HostTokenScoped wires the agent handler behind a fake host-token middleware and confirms a token for host-a sees
// only host-a's commands: ?host_id=host-b query spoofing is ignored. Inherits the phase-1 TestHostScopedCommandAccess regression
// coverage.
func TestAgentRoutes_HostTokenScoped(t *testing.T) {
	t.Parallel()
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

// TestOperatorRoutes_PostAndGet covers the session-gated surface. Tests don't wrap in real session+CSRF middleware: those are owned
// by identity and tested there. Here we just confirm the routes are wired and the bodies + audit payloads match.
func TestOperatorRoutes_PostAndGet(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	_, err := bootstrap.New(bootstrap.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB")
}

// withHostID wraps mux in a tiny middleware that pins host_id on the request context the way the real endpoint.HostToken middleware
// does. Lets the agent handler tests run without spinning up endpoint bootstrap + a token mint.
func withHostID(next http.Handler, hostID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := endpointapi.WithHostIDForTest(r.Context(), hostID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func intStr(n int64) string { return strconv.FormatInt(n, 10) }

// stubVerifier satisfies gateway.TokenVerifier for the BuildControlGateway wiring test.
type stubVerifier struct{}

func (stubVerifier) VerifyToken(context.Context, string) (string, error) { return "host-a", nil }

// TestBuildControlGateway covers the response context's construction of the control-channel gateway and the fast-path notifier wiring.
func TestBuildControlGateway(t *testing.T) {
	t.Parallel()
	r := newResponse(t, nil)

	gw := r.BuildControlGateway(stubVerifier{}, nil)
	require.NotNil(t, gw)
	require.NotNil(t, gw.GRPCServer())

	// After wiring, an insert drives the fast-path notifier without error (delivery itself needs a live connection, covered in the
	// gateway package tests).
	_, err := r.Service().Insert(t.Context(), "host-a", "kill_process", json.RawMessage(`{"pid":1}`))
	require.NoError(t, err)
}

// TestControlGatewayPushLifecycle_RealMySQL is the integration-fidelity counterpart to the gateway package's in-memory delivery test
// (issue #477, tasks.md 5.1): a command queued for a connected agent is pushed over the bidirectional stream and its ack-then-complete
// outcomes are applied through the REAL response service against MySQL, so the commands row walks pending -> acked -> completed exactly as
// the poll path (TestUpdateStatus_LifecycleHappyPath) does. The gateway is driven through its production entry point (grpc.Server.ServeHTTP
// behind a net/http HTTP/2 server speaking cleartext h2c, how cmd/main multiplexes it onto the shared listener), and the command is queued
// via Service.Insert, whose fast-path notifier (wired by BuildControlGateway) pushes it to the live connection.
func TestControlGatewayPushLifecycle_RealMySQL(t *testing.T) {
	t.Parallel()
	r := newResponse(t, nil)
	gw := r.BuildControlGateway(stubVerifier{}, nil)

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	httpSrv := &http.Server{Handler: gw, Protocols: protocols, ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpSrv.Serve(lis) }()
	runCtx, runCancel := context.WithCancel(t.Context())
	go gw.Run(runCtx)
	t.Cleanup(func() {
		runCancel()
		gw.Stop()
		// Bound the shutdown so a regression that wedges the stream fails the test instead of hanging the run, mirroring
		// httpserver.RunAndShutdown's own timeout-bounded shutdown context.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(runCtx), 15*time.Second)
		defer shutdownCancel()
		require.NoError(t, httpSrv.Shutdown(shutdownCtx))
		require.ErrorIs(t, <-serveDone, http.ErrServerClosed)
	})

	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })

	streamCtx, streamCancel := context.WithCancel(controlConnectCtx("tok-a"))
	defer streamCancel()
	stream, err := control.NewControlChannelClient(cc).Connect(streamCtx)
	require.NoError(t, err)

	// Queue a command through the real service; the fast-path notifier pushes it to the live connection (the 1s watch is the backstop).
	ctx := t.Context()
	id, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{"pid":42}`))
	require.NoError(t, err)

	// Server -> agent: the pushed command arrives over the stream, byte-stable with the commands row.
	frame, err := stream.Recv()
	require.NoError(t, err)
	cmd := frame.GetCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, id, cmd.GetId())
	assert.Equal(t, "kill_process", cmd.GetCommandType())
	assert.Equal(t, "host-a", cmd.GetHostId())
	assert.JSONEq(t, `{"pid":42}`, string(cmd.GetPayload()))

	// The row is still pending until the agent reports an outcome.
	got, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusPending, got.Status)

	// Agent -> server: ack, then complete. Both flow through the unchanged UpdateStatus lifecycle against MySQL.
	require.NoError(t, stream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{Outcome: &control.Outcome{
		Id: id, Status: string(api.StatusAcked),
	}}}))
	require.Eventually(t, func() bool {
		got, err := r.Service().Get(ctx, id)
		return err == nil && got.Status == api.StatusAcked
	}, 2*time.Second, 10*time.Millisecond, "ack applied to MySQL over the stream")

	require.NoError(t, stream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{Outcome: &control.Outcome{
		Id: id, Status: string(api.StatusCompleted), Result: []byte(`{"killed_pid":42}`),
	}}}))
	require.Eventually(t, func() bool {
		got, err := r.Service().Get(ctx, id)
		return err == nil && got.Status == api.StatusCompleted
	}, 2*time.Second, 10*time.Millisecond, "completion applied to MySQL over the stream")

	// Final DB state matches the poll path: terminal completed, with ack/complete timestamps and the result persisted.
	got, err = r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusCompleted, got.Status)
	require.NotNil(t, got.AckedAt)
	require.NotNil(t, got.CompletedAt)
	assert.JSONEq(t, `{"killed_pid":42}`, string(got.Result))
}

// controlConnectCtx builds the outgoing gRPC context carrying the host bearer token the gateway's auth interceptor reads from metadata.
func controlConnectCtx(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
}
