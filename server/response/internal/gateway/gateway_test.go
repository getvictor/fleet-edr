package gateway

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/fleetdm/edr/internal/control"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/response/api"
)

// fakeSource is an in-memory CommandSource. UpdateStatus drops the command from the pending set, mirroring the real transition out of
// 'pending' so a delivered command is not re-pushed on the next watch tick.
type fakeSource struct {
	mu      sync.Mutex
	pending map[string][]api.Command
	updates []api.UpdateStatusRequest
}

func newFakeSource() *fakeSource { return &fakeSource{pending: make(map[string][]api.Command)} }

func (f *fakeSource) addPending(cmd api.Command) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd.Status = api.StatusPending
	f.pending[cmd.HostID] = append(f.pending[cmd.HostID], cmd)
}

func (f *fakeSource) ListPendingForHosts(_ context.Context, hostIDs []string) ([]api.Command, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []api.Command
	for _, h := range hostIDs {
		out = append(out, f.pending[h]...)
	}
	return out, nil
}

func (f *fakeSource) UpdateStatus(_ context.Context, req api.UpdateStatusRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, req)
	remaining := f.pending[req.HostID][:0]
	for _, c := range f.pending[req.HostID] {
		if c.ID != req.ID {
			remaining = append(remaining, c)
		}
	}
	f.pending[req.HostID] = remaining
	return nil
}

func (f *fakeSource) updateCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.updates)
}

// fakeVerifier maps tokens to host ids and supports revoking a token mid-connection.
type fakeVerifier struct {
	mu      sync.Mutex
	valid   map[string]string
	revoked map[string]bool
}

func newFakeVerifier() *fakeVerifier {
	return &fakeVerifier{valid: make(map[string]string), revoked: make(map[string]bool)}
}

func (v *fakeVerifier) add(token, hostID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.valid[token] = hostID
}

func (v *fakeVerifier) revoke(token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.revoked[token] = true
}

func (v *fakeVerifier) VerifyToken(_ context.Context, token string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.revoked[token] {
		return "", endpointapi.ErrInvalidToken
	}
	if h, ok := v.valid[token]; ok {
		return h, nil
	}
	return "", endpointapi.ErrInvalidToken
}

// newTestGateway starts a Gateway over an in-memory bufconn listener and returns a client-side dialer. Intervals are tightened so the
// watch and revocation re-check fire fast under test.
func newTestGateway(t *testing.T, src CommandSource, verifier TokenVerifier) (*Gateway, func(ctx context.Context, token string) control.ControlChannelClient) {
	t.Helper()
	g := New(Deps{Source: src, Verifier: verifier})
	g.watchInterval = 20 * time.Millisecond
	g.revocationInterval = 20 * time.Millisecond
	g.livenessInterval = 20 * time.Millisecond

	lis := bufconn.Listen(1 << 20)
	go func() { _ = g.GRPCServer().Serve(lis) }()

	runCtx, runCancel := context.WithCancel(t.Context())
	go g.Run(runCtx)

	t.Cleanup(func() {
		runCancel()
		g.GRPCServer().Stop()
		_ = lis.Close()
	})

	dial := func(ctx context.Context, token string) control.ControlChannelClient {
		cc, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cc.Close() })
		return control.NewControlChannelClient(cc)
	}
	return g, dial
}

func connectCtx(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
}

// recordingHeartbeat counts last-seen bumps per host so the liveness test can assert connection presence advances last-seen (and that
// the bumps stop once the connection drops), standing in for the detection.RecordHostSeen closure cmd/main wires in production.
type recordingHeartbeat struct {
	mu    sync.Mutex
	calls map[string]int
}

func newRecordingHeartbeat() *recordingHeartbeat {
	return &recordingHeartbeat{calls: make(map[string]int)}
}

func (h *recordingHeartbeat) bump(_ context.Context, hostID string, _ time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls[hostID]++
	return nil
}

func (h *recordingHeartbeat) count(hostID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[hostID]
}

// TestGatewayLiveness pins connection-presence liveness (issue #477, tasks.md 5.7): while a host holds a control connection the gateway
// advances its last-seen via the injected heartbeat WITHOUT any command poll or telemetry upload, and once the connection drops the bumps
// stop so the host ages to offline. Delivery and revocation intervals are pushed out of the way so the test isolates the liveness path.
func TestGatewayLiveness(t *testing.T) {
	t.Parallel()
	hb := newRecordingHeartbeat()
	ver := newFakeVerifier()
	ver.add("tok-a", "host-a")

	g := New(Deps{Source: newFakeSource(), Verifier: ver, Heartbeat: hb.bump})
	g.livenessInterval = 20 * time.Millisecond
	g.watchInterval = time.Hour      // the watch would only deliver commands; keep it out of this test
	g.revocationInterval = time.Hour // the token stays valid; don't let the re-check tear the connection down

	lis := bufconn.Listen(1 << 20)
	go func() { _ = g.GRPCServer().Serve(lis) }()
	runCtx, runCancel := context.WithCancel(t.Context())
	go g.Run(runCtx)
	t.Cleanup(func() {
		runCancel()
		g.GRPCServer().Stop()
		_ = lis.Close()
	})

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })

	streamCtx, streamCancel := context.WithCancel(connectCtx("tok-a"))
	_, err = control.NewControlChannelClient(cc).Connect(streamCtx)
	require.NoError(t, err)

	// Connection presence alone advances last-seen: no ListForHost poll, no upload happened, yet the heartbeat fires (once on connect,
	// then on the liveness cadence).
	require.Eventually(t, func() bool { return hb.count("host-a") >= 2 }, 2*time.Second, 5*time.Millisecond,
		"connection presence advances last-seen without a poll or upload")

	// Disconnect: the connection deregisters and the bumps stop, so the host's last-seen no longer advances and it ages to offline.
	streamCancel()
	require.Eventually(t, func() bool { return g.reg.len() == 0 }, 2*time.Second, 10*time.Millisecond)
	settled := hb.count("host-a")
	time.Sleep(4 * g.livenessInterval) // let several liveness ticks pass with no live connection
	assert.Equal(t, settled, hb.count("host-a"), "no last-seen bump after the connection drops")
}

func TestGateway(t *testing.T) {
	t.Parallel()
	t.Run("valid token delivers a pending command and records its outcome", func(t *testing.T) {
		t.Parallel()
		src := newFakeSource()
		ver := newFakeVerifier()
		ver.add("tok-a", "host-a")
		src.addPending(api.Command{ID: 7, HostID: "host-a", CommandType: "kill_process", Payload: []byte(`{"pid":42}`)})
		_, dial := newTestGateway(t, src, ver)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := dial(ctx, "tok-a").Connect(connectCtx("tok-a"))
		require.NoError(t, err)

		frame, err := stream.Recv()
		require.NoError(t, err)
		cmd := frame.GetCommand()
		require.NotNil(t, cmd)
		assert.Equal(t, int64(7), cmd.GetId())
		assert.Equal(t, "kill_process", cmd.GetCommandType())
		assert.Equal(t, "host-a", cmd.GetHostId())
		assert.JSONEq(t, `{"pid":42}`, string(cmd.GetPayload()))

		require.NoError(t, stream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{Outcome: &control.Outcome{
			Id: 7, Status: string(api.StatusAcked),
		}}}))
		require.NoError(t, stream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{Outcome: &control.Outcome{
			Id: 7, Status: string(api.StatusCompleted), Result: []byte(`{"killed_pid":42}`),
		}}}))

		require.Eventually(t, func() bool { return src.updateCount() == 2 }, 2*time.Second, 10*time.Millisecond)
		src.mu.Lock()
		defer src.mu.Unlock()
		assert.Equal(t, api.StatusAcked, src.updates[0].Status)
		assert.Equal(t, "host-a", src.updates[0].HostID)
		assert.Equal(t, api.StatusCompleted, src.updates[1].Status)
		assert.JSONEq(t, `{"killed_pid":42}`, string(src.updates[1].Result))
	})

	t.Run("invalid token is rejected with Unauthenticated", func(t *testing.T) {
		t.Parallel()
		_, dial := newTestGateway(t, newFakeSource(), newFakeVerifier())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := dial(ctx, "bad").Connect(connectCtx("bad"))
		require.NoError(t, err)
		_, err = stream.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("missing token is rejected with Unauthenticated", func(t *testing.T) {
		t.Parallel()
		_, dial := newTestGateway(t, newFakeSource(), newFakeVerifier())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := dial(ctx, "").Connect(context.Background()) // no authorization metadata
		require.NoError(t, err)
		_, err = stream.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("second connection for the same host evicts the first", func(t *testing.T) {
		t.Parallel()
		src := newFakeSource()
		ver := newFakeVerifier()
		ver.add("tok-a", "host-a")
		g, dial := newTestGateway(t, src, ver)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		first, err := dial(ctx, "tok-a").Connect(connectCtx("tok-a"))
		require.NoError(t, err)
		require.Eventually(t, func() bool { return g.reg.len() == 1 }, 2*time.Second, 10*time.Millisecond)

		second, err := dial(ctx, "tok-a").Connect(connectCtx("tok-a"))
		require.NoError(t, err)
		// The first stream is torn down by the eviction; its Recv returns an error.
		_, err = first.Recv()
		require.Error(t, err)
		// The registry still holds exactly one connection for the host (the second).
		require.Eventually(t, func() bool { return g.reg.len() == 1 }, 2*time.Second, 10*time.Millisecond)
		// The second connection is live: a command queued for the host is delivered on it.
		src.addPending(api.Command{ID: 9, HostID: "host-a", CommandType: "kill_process", Payload: []byte(`{"pid":1}`)})
		g.Notify("host-a")
		frame, err := second.Recv()
		require.NoError(t, err)
		assert.Equal(t, int64(9), frame.GetCommand().GetId())
	})

	t.Run("client disconnect deregisters the connection", func(t *testing.T) {
		t.Parallel()
		src := newFakeSource()
		ver := newFakeVerifier()
		ver.add("tok-a", "host-a")
		g, dial := newTestGateway(t, src, ver)

		streamCtx, streamCancel := context.WithCancel(connectCtx("tok-a"))
		_, err := dial(streamCtx, "tok-a").Connect(streamCtx)
		require.NoError(t, err)
		require.Eventually(t, func() bool { return g.reg.len() == 1 }, 2*time.Second, 10*time.Millisecond)

		streamCancel() // client goes away; the server's Recv ends and the connection is removed from the registry
		require.Eventually(t, func() bool { return g.reg.len() == 0 }, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("revoked token tears down the connection", func(t *testing.T) {
		t.Parallel()
		src := newFakeSource()
		ver := newFakeVerifier()
		ver.add("tok-a", "host-a")
		src.addPending(api.Command{ID: 1, HostID: "host-a", CommandType: "kill_process", Payload: []byte(`{"pid":1}`)})
		_, dial := newTestGateway(t, src, ver)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := dial(ctx, "tok-a").Connect(connectCtx("tok-a"))
		require.NoError(t, err)
		// First receive establishes the connection (the interceptor verified the still-valid token). Only then revoke, so the teardown
		// comes from the maintenance re-check (Unavailable), not from the connect-time interceptor (Unauthenticated).
		_, err = stream.Recv()
		require.NoError(t, err)
		ver.revoke("tok-a")
		_, err = stream.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}

// TestGatewayServeAndStop exercises the production serve path: New, Serve on a real TCP listener, a client dialing with a token,
// command delivery over a BIDIRECTIONAL stream, and a graceful Stop. This serves the gateway through its production entry point,
// grpc.Server.ServeHTTP behind a net/http HTTP/2 server (how cmd/main multiplexes it onto the shared HTTPS listener), so it pins that
// the long-lived bidi control stream works over net/http's HTTP/2 (the documented ServeHTTP caveat), not only over gRPC's own
// transport. TLS is terminated upstream in production; here the server speaks cleartext HTTP/2 (h2c) and the client dials insecure.
func TestGatewayServeAndStop(t *testing.T) {
	t.Parallel()
	src := newFakeSource()
	ver := newFakeVerifier()
	ver.add("tok-a", "host-a")
	src.addPending(api.Command{ID: 5, HostID: "host-a", CommandType: "kill_process", Payload: []byte(`{"pid":9}`)})

	g := New(Deps{Source: src, Verifier: ver})
	g.watchInterval = 20 * time.Millisecond

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// Serve the gateway exactly as production does: a net/http server with cleartext HTTP/2 enabled, dispatching to g.ServeHTTP.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	httpSrv := &http.Server{Handler: g, Protocols: protocols, ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpSrv.Serve(lis) }()
	runCtx, runCancel := context.WithCancel(t.Context())
	defer runCancel()
	go g.Run(runCtx)

	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	streamCtx, streamCancel := context.WithCancel(connectCtx("tok-a"))
	stream, err := control.NewControlChannelClient(cc).Connect(streamCtx)
	require.NoError(t, err)
	// Server -> client: the pushed command arrives over the bidi stream.
	frame, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, int64(5), frame.GetCommand().GetId())
	// Client -> server: report an outcome on the same stream, exercising the other direction of the full-duplex stream over ServeHTTP.
	require.NoError(t, stream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{
		Outcome: &control.Outcome{Id: 5, Status: "completed"},
	}}))
	// The server must actually receive and apply the outcome (recvLoop -> UpdateStatus): without this assertion the test would pass even
	// if the client->server direction were broken, since Send buffers locally.
	require.Eventually(t, func() bool { return src.updateCount() >= 1 }, 2*time.Second, 10*time.Millisecond,
		"server applies the outcome reported over the bidi stream")

	streamCancel() // end the client stream so Stop's stream-cancel completes promptly
	g.Stop()
	require.NoError(t, httpSrv.Shutdown(context.WithoutCancel(runCtx)))
	require.ErrorIs(t, <-serveDone, http.ErrServerClosed, "Serve returns ErrServerClosed after Shutdown, not an unexpected failure")
}
