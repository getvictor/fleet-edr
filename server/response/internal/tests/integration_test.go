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
	"github.com/fleetdm/edr/server/response/internal/service"
	"github.com/jmoiron/sqlx"
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
	"github.com/fleetdm/edr/server/response/internal/gateway"
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

// newResponseAndDB is newResponse plus the handle to the same database, for tests that have to age a row rather than wait for it.
func newResponseAndDB(t *testing.T) (*bootstrap.Response, *sqlx.DB) {
	t.Helper()
	s := full.Open(t)
	r, err := bootstrap.New(bootstrap.Deps{DB: s, AuthZ: allowAllAuthZ{}})
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r, s
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
// spec:agent-control-channel/delivery-is-at-least-once-and-idempotent-by-command-identity/an-outcome-that-is-not-a-valid-transition-is-rejected
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
// spec:agent-control-channel/commands-on-the-connection-are-scoped-to-the-authenticated-host/an-outcome-report-for-another-host-s-command-is-rejected
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
// spec:agent-control-channel/queued-commands-are-delivered-over-the-connection-in-real-time/command-queued-on-the-connection-holding-replica-is-delivered-immediately
// spec:agent-control-channel/command-outcomes-are-reported-over-the-same-connection-with-the-same-lifecycle/acknowledge-then-complete-over-the-connection
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

// serveGateway serves gw over an h2c net/http server on a fresh loopback listener and starts its watch loop, exactly as cmd/main
// multiplexes the control gateway onto the shared HTTPS listener (grpc.Server.ServeHTTP behind net/http's cleartext HTTP/2). The
// returned stop tears the gateway and its listener down so a fresh gateway (modelling the same replica after a restart, or a peer
// replica) can take over the same MySQL store; it returns only after the serve goroutine has observed http.ErrServerClosed.
func serveGateway(t *testing.T, gw *gateway.Gateway) (addr string, stop func()) {
	t.Helper()
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
	stop = func() {
		runCancel()
		gw.Stop()
		// Bound the shutdown so a regression that wedges the stream fails the test instead of hanging the run, mirroring
		// httpserver.RunAndShutdown's own timeout-bounded shutdown context.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(runCtx), 15*time.Second)
		defer shutdownCancel()
		require.NoError(t, httpSrv.Shutdown(shutdownCtx))
		require.ErrorIs(t, <-serveDone, http.ErrServerClosed)
	}
	return lis.Addr().String(), stop
}

// TestGatewayLossReconnectNoCommandLoss_RealMySQL pins the ADR-0010 control-gateway carve-out: the gateway is the one sanctioned
// stateful tier, holding only ephemeral per-connection state (the live socket and the in-flight command identifiers), while every
// command's durable state lives in the shared MySQL store. So losing a gateway (and its whole in-memory connection registry) before a
// queued command is acknowledged loses NO command: the row stays pending in MySQL, is servable meanwhile over the retained polled
// command path, and is re-delivered when the host reconnects to a fresh gateway. This is the integration-fidelity counterpart to the
// gateway package's in-memory disconnect/deregister test, driven through the production entry point (grpc.Server.ServeHTTP behind an
// h2c net/http server) against a real database.
// spec:server-availability/the-server-holds-no-in-process-state-that-survives-a-request-lifetime/losing-the-gateway-forces-reconnect-without-command-loss
func TestGatewayLossReconnectNoCommandLoss_RealMySQL(t *testing.T) {
	t.Parallel()
	r := newResponse(t, nil)
	ctx := t.Context()

	// First gateway: the replica that will be lost. BuildControlGateway wires the fast-path notifier so an Insert on this replica pushes
	// to a locally-held connection immediately (the 1s watch is the backstop).
	firstGateway := r.BuildControlGateway(stubVerifier{}, nil)
	firstAddr, stopFirst := serveGateway(t, firstGateway)
	// Register teardown immediately so an early require failure between here and the intentional mid-test loss below cannot leak the
	// running server/stream into other parallel tests. stopFirst is wrapped in sync.OnceFunc because the test also stops it explicitly to
	// model the gateway loss; the Once makes the later cleanup call a no-op (serveGateway's stop drains its serveDone channel exactly once).
	stopFirstOnce := sync.OnceFunc(stopFirst)
	t.Cleanup(stopFirstOnce)

	firstConn, err := grpc.NewClient(firstAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = firstConn.Close() })
	// A timeout on the stream context bounds the blocking Recv below, so a delivery regression fails in seconds instead of hanging until
	// the global test timeout. cancelFirstStream still tears the stream down early to model the gateway loss.
	firstStreamCtx, cancelFirstStream := context.WithTimeout(controlConnectCtx("tok-a"), 10*time.Second)
	t.Cleanup(cancelFirstStream)
	firstStream, err := control.NewControlChannelClient(firstConn).Connect(firstStreamCtx)
	require.NoError(t, err)

	// Queue a command; the connected agent receives it over the stream but reports no outcome, so the row stays pending. The gateway now
	// holds only the ephemeral in-flight marker for it; the durable row lives in MySQL.
	id, err := r.Service().Insert(ctx, "host-a", "kill_process", json.RawMessage(`{"pid":42}`))
	require.NoError(t, err)

	frame, err := firstStream.Recv()
	require.NoError(t, err)
	require.NotNil(t, frame.GetCommand())
	require.Equal(t, id, frame.GetCommand().GetId())

	pushed, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, api.StatusPending, pushed.Status, "delivered but unacknowledged: the row is still pending in the store")

	// Lose the gateway and its whole in-memory connection registry (the sanctioned stateful tier goes away), before any outcome lands.
	cancelFirstStream()
	require.NoError(t, firstConn.Close())
	stopFirstOnce()

	// The queued command survived the in-process loss: durable state lives in MySQL, not in the gateway's memory. This is the
	// load-bearing assertion.
	afterLoss, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusPending, afterLoss.Status, "command survives gateway loss because its state is durable, not gateway-held")

	// Meanwhile the agent falls back to the polled command path, which still returns the pending command with no gateway present at all.
	polled, err := r.Service().ListForHost(ctx, "host-a", api.StatusPending)
	require.NoError(t, err)
	require.Len(t, polled, 1, "the retained poll path still serves the pending command while no gateway holds a connection")
	assert.Equal(t, id, polled[0].ID)

	// A fresh gateway comes up (the same replica after a restart, or a peer replica: either way it shares this MySQL store) and the host
	// reconnects. The still-pending command is re-delivered over the new stream from the shared store: no command was lost.
	secondGateway := r.BuildControlGateway(stubVerifier{}, nil)
	secondAddr, stopSecond := serveGateway(t, secondGateway)
	t.Cleanup(stopSecond)

	secondConn, err := grpc.NewClient(secondAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = secondConn.Close() })
	secondStreamCtx, cancelSecondStream := context.WithTimeout(controlConnectCtx("tok-a"), 10*time.Second)
	defer cancelSecondStream()
	secondStream, err := control.NewControlChannelClient(secondConn).Connect(secondStreamCtx)
	require.NoError(t, err)

	// The fresh gateway pushes the still-pending command on connect (backlog) or via the 1s watch backstop; its in-flight bookkeeping is
	// its own, so the prior gateway's lost marker does not suppress re-delivery.
	redelivered, err := secondStream.Recv()
	require.NoError(t, err)
	require.NotNil(t, redelivered.GetCommand())
	assert.Equal(t, id, redelivered.GetCommand().GetId(), "the pending command is re-delivered on reconnect from the shared store")

	// The agent now reports its full lifecycle over the reconnected stream; both outcomes flow through the unchanged UpdateStatus rules
	// against MySQL, so the row walks pending to acked to completed exactly as the poll path does.
	require.NoError(t, secondStream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{Outcome: &control.Outcome{
		Id: id, Status: string(api.StatusAcked),
	}}}))
	require.Eventually(t, func() bool {
		got, err := r.Service().Get(ctx, id)
		return err == nil && got.Status == api.StatusAcked
	}, 5*time.Second, 20*time.Millisecond, "ack applied to MySQL over the reconnected stream")

	require.NoError(t, secondStream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{Outcome: &control.Outcome{
		Id: id, Status: string(api.StatusCompleted), Result: []byte(`{"killed_pid":42}`),
	}}}))
	require.Eventually(t, func() bool {
		got, err := r.Service().Get(ctx, id)
		return err == nil && got.Status == api.StatusCompleted
	}, 5*time.Second, 20*time.Millisecond, "completion applied to MySQL over the reconnected stream")

	// Final DB state confirms the command completed its lifecycle after the gateway loss and reconnect: nothing was lost.
	final, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusCompleted, final.Status)
	require.NotNil(t, final.AckedAt)
	require.NotNil(t, final.CompletedAt)
	assert.JSONEq(t, `{"killed_pid":42}`, string(final.Result))
}

// A command withdrawn before any agent picked it up reaches a terminal state distinct from failed, and stops being delivered.
//
// Without this an operator could only wait: a host may be offline, or holding a control stream the server has forgotten (issue #711),
// and a kill_process addresses a pid. Delivered long after it was issued it can land on a recycled pid and terminate an unrelated
// process, so being unable to withdraw one is a safety problem rather than a tidiness problem.
// spec:agent-control-channel/a-queued-command-can-be-withdrawn-and-ages-out-rather-than-being-delivered-late/an-operator-withdraws-a-command-no-agent-has-taken
func TestCancel_WithdrawsAPendingCommandAndStopsDelivery(t *testing.T) {
	t.Parallel()
	r := newResponse(t, nil)
	ctx := t.Context()

	id, err := r.Service().Insert(ctx, "host-cancel", "kill_process", json.RawMessage(`{"pid":1234}`))
	require.NoError(t, err)

	require.NoError(t, r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{ID: id, HostID: "host-cancel", Status: api.StatusCancelled}))

	cmd, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusCancelled, cmd.Status, "cancelled is its own state: nothing ran on the host")

	pending, err := r.Service().ListForHost(ctx, "host-cancel", api.StatusPending)
	require.NoError(t, err)
	assert.Empty(t, pending, "a cancelled command is no longer offered for delivery")
}

// Once an agent has acked a command it may already have applied the side effect, so recording it as cancelled would tell the operator
// nothing ran when something may well have.
// spec:agent-control-channel/a-queued-command-can-be-withdrawn-and-ages-out-rather-than-being-delivered-late/withdrawal-is-refused-once-the-agent-has-the-command
func TestCancel_RefusedOnceTheAgentHasIt(t *testing.T) {
	t.Parallel()
	r := newResponse(t, nil)
	ctx := t.Context()

	id, err := r.Service().Insert(ctx, "host-acked", "kill_process", json.RawMessage(`{"pid":1234}`))
	require.NoError(t, err)
	require.NoError(t, r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{ID: id, HostID: "host-acked", Status: api.StatusAcked}))

	err = r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{ID: id, HostID: "host-acked", Status: api.StatusCancelled})
	require.ErrorIs(t, err, api.ErrInvalidStatusTransition)

	cmd, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusAcked, cmd.Status, "the agent still owns it")
}

// A command that waited past the delivery window is aged out rather than handed to an agent late, and the ageing happens on the
// delivery read itself so it needs no sweep loop and no leader election.
// spec:agent-control-channel/a-queued-command-can-be-withdrawn-and-ages-out-rather-than-being-delivered-late/a-command-that-waited-too-long-is-aged-out-instead-of-delivered
func TestPendingCommandsAreAgedOutRatherThanDeliveredLate(t *testing.T) {
	t.Parallel()
	r, db := newResponseAndDB(t)
	ctx := t.Context()

	stale, err := r.Service().Insert(ctx, "host-ttl", "kill_process", json.RawMessage(`{"pid":1234}`))
	require.NoError(t, err)
	fresh, err := r.Service().Insert(ctx, "host-ttl", "kill_process", json.RawMessage(`{"pid":5678}`))
	require.NoError(t, err)

	// Backdate the first past the window. Rewriting created_at is the only way to age a row without sleeping for an hour.
	_, err = db.ExecContext(ctx,
		"UPDATE commands SET created_at = NOW(6)-INTERVAL ? SECOND WHERE id = ?",
		int((service.PendingCommandTTL + time.Minute).Seconds()), stale)
	require.NoError(t, err)

	pending, err := r.Service().ListForHost(ctx, "host-ttl", api.StatusPending)
	require.NoError(t, err)
	require.Len(t, pending, 1, "only the command still inside the window is deliverable")
	assert.Equal(t, fresh, pending[0].ID)

	aged, err := r.Service().Get(ctx, stale)
	require.NoError(t, err)
	assert.Equal(t, api.StatusExpired, aged.Status, "the operator can see WHY it never ran, not just that it is gone")
}

// Ageing out must not touch a command an agent already owns: it may have applied the side effect, and the record has to keep saying so.
// spec:agent-control-channel/a-queued-command-can-be-withdrawn-and-ages-out-rather-than-being-delivered-late/ageing-out-does-not-disturb-a-command-the-agent-already-owns
func TestAgeingOutLeavesAnAckedCommandAlone(t *testing.T) {
	t.Parallel()
	r, db := newResponseAndDB(t)
	ctx := t.Context()

	id, err := r.Service().Insert(ctx, "host-ttl-acked", "kill_process", json.RawMessage(`{"pid":1234}`))
	require.NoError(t, err)
	require.NoError(t, r.Service().UpdateStatus(ctx, api.UpdateStatusRequest{ID: id, HostID: "host-ttl-acked", Status: api.StatusAcked}))
	_, err = db.ExecContext(ctx,
		"UPDATE commands SET created_at = NOW(6)-INTERVAL ? SECOND WHERE id = ?",
		int((service.PendingCommandTTL + time.Minute).Seconds()), id)
	require.NoError(t, err)

	_, err = r.Service().ListForHost(ctx, "host-ttl-acked", api.StatusPending)
	require.NoError(t, err)

	cmd, err := r.Service().Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusAcked, cmd.Status, "an acked command is owned by the agent and is not aged out")
}
