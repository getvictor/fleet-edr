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
// recvCommand reads until a command frame arrives, skipping heartbeats. Heartbeats are ordinary traffic on this stream now (they are
// what tells an agent the server still holds its connection, issue #711), so a test that wants the next COMMAND has to say so rather
// than assume the next frame is one.
func recvCommand(t *testing.T, stream control.ControlChannel_ConnectClient) (*control.Command, error) {
	t.Helper()
	for {
		frame, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		if cmd := frame.GetCommand(); cmd != nil {
			return cmd, nil
		}
	}
}

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
// spec:agent-control-channel/connection-presence-is-authoritative-host-liveness/a-connected-host-s-last-seen-advances-without-polling
// spec:agent-control-channel/connection-presence-is-authoritative-host-liveness/disconnect-reflects-in-online-status
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
	t.Cleanup(streamCancel) // always tear the client stream down, even if the test fails before the disconnect step
	_, err = control.NewControlChannelClient(cc).Connect(streamCtx)
	require.NoError(t, err)

	// Connection presence alone advances last-seen: no ListForHost poll, no upload happened, yet the heartbeat fires (once on connect,
	// then on the liveness cadence).
	require.Eventually(t, func() bool { return hb.count("host-a") >= 2 }, 2*time.Second, 5*time.Millisecond,
		"connection presence advances last-seen without a poll or upload")

	// Disconnect: the connection deregisters and the maintain goroutine stops bumping last-seen, so the host's last-seen no longer
	// advances and it ages to offline. Wait for the bump count to go quiescent before snapshotting: the maintain select can take one last
	// liveness tick after cancellation (select picks a ready case at random), so snapshotting immediately after reg.len()==0 could race a
	// final in-flight bump.
	streamCancel()
	require.Eventually(t, func() bool { return g.reg.len() == 0 }, 2*time.Second, 10*time.Millisecond)
	var settled int
	require.Eventually(t, func() bool {
		c := hb.count("host-a")
		if c == settled {
			return true
		}
		settled = c
		return false
	}, 2*time.Second, 2*g.livenessInterval, "last-seen bumps stop after disconnect")
	time.Sleep(4 * g.livenessInterval) // confirm no further bump over several liveness ticks with no live connection
	assert.Equal(t, settled, hb.count("host-a"), "no last-seen bump after the connection drops")
}

func TestGateway(t *testing.T) {
	t.Parallel()
	// spec:agent-control-channel/the-agent-holds-a-persistent-authenticated-control-connection/connection-opens-with-a-valid-host-token
	// spec:agent-control-channel/queued-commands-are-delivered-over-the-connection-in-real-time/command-queued-for-a-connected-host-is-pushed-promptly
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

	// spec:agent-control-channel/the-agent-holds-a-persistent-authenticated-control-connection/connection-is-refused-for-an-invalid-or-expired-token
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

	// spec:agent-control-channel/the-agent-holds-a-persistent-authenticated-control-connection/a-reconnect-replaces-the-prior-connection-for-the-same-host
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

	// The agent cannot otherwise tell a quiet fleet from a stream this replica has forgotten: the gateway runs over the shared HTTPS
	// listener where net/http answers HTTP/2 keepalive PINGs itself, so the ping keeps passing on a connection that no longer exists
	// here. The heartbeat's arrival IS the proof, so it has to actually be sent (issue #711).
	//
	// spec:agent-control-channel/the-connection-detects-and-recovers-from-silent-failure/an-idle-connection-still-carries-proof-that-the-server-holds-it
	t.Run("an idle connection still receives heartbeats", func(t *testing.T) {
		t.Parallel()
		src := newFakeSource()
		ver := newFakeVerifier()
		ver.add("tok-hb", "host-hb")
		_, dial := newTestGateway(t, src, ver)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Nothing pending, so any frame that arrives can only be a heartbeat.
		stream, err := dial(ctx, "tok-hb").Connect(connectCtx("tok-hb"))
		require.NoError(t, err)

		// Bounded rather than a bare Recv: with no heartbeat there is nothing to receive, and an unbounded read turns a missing
		// heartbeat into a hung suite instead of a failed assertion.
		type recvResult struct {
			frame *control.ServerFrame
			err   error
		}
		got := make(chan recvResult, 1)
		go func() {
			f, rerr := stream.Recv()
			got <- recvResult{f, rerr}
		}()
		select {
		case res := <-got:
			require.NoError(t, res.err)
			assert.NotNil(t, res.frame.GetHeartbeat(), "an idle stream must still carry proof that the server holds it")
			assert.Nil(t, res.frame.GetCommand())
		case <-time.After(2 * time.Second):
			t.Fatal("no heartbeat arrived on an idle connection")
		}
	})

	// spec:agent-control-channel/a-revoked-or-expired-token-terminates-the-connection/revoking-a-token-closes-the-connection
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
		_, err = recvCommand(t, stream)
		require.NoError(t, err)
		ver.revoke("tok-a")
		_, err = recvCommand(t, stream)
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})

	// A command queued on a different replica never signals this replica's fast path (no Notify): the connection-holding replica must
	// still discover and deliver it on its periodic watch tick. Here addPending mutates only the pending map, exactly as a cross-replica
	// insert looks to this replica, and with nothing pending at connect the connect-time backlog push delivers nothing, so the sole path
	// to the stream is the watch sweep firing on newTestGateway's 20ms interval.
	// spec:agent-control-channel/queued-commands-are-delivered-over-the-connection-in-real-time/command-queued-on-another-replica-is-delivered-within-the-watch-interval
	t.Run("command queued on another replica is delivered by the watch sweep without a notify", func(t *testing.T) {
		t.Parallel()
		src := newFakeSource()
		ver := newFakeVerifier()
		ver.add("tok-a", "host-a")
		g, dial := newTestGateway(t, src, ver)

		// A bounded stream context so a delivery regression fails fast (Recv returns DeadlineExceeded) instead of hanging the test. The
		// 5s bound is comfortably above the 20ms watch interval, so a healthy watch sweep always beats it.
		streamCtx, streamCancel := context.WithTimeout(connectCtx("tok-a"), 5*time.Second)
		defer streamCancel()
		stream, err := dial(streamCtx, "tok-a").Connect(streamCtx)
		require.NoError(t, err)

		// Wait until the server has registered the connection so the watch ticker sweeps this host, and so the connect-time backlog push
		// (which saw an empty pending set) has already run and delivered nothing.
		require.Eventually(t, func() bool { return g.reg.len() == 1 }, 2*time.Second, 10*time.Millisecond)

		// Queue the command AFTER connect with NO Notify: this models an operator action landing on a peer replica. The command reaches
		// the stream only because the watch ticker calls ListPendingForHosts for the connected host and pushes it.
		src.addPending(api.Command{ID: 11, HostID: "host-a", CommandType: "isolate_host", Payload: []byte(`{"mode":"full"}`)})

		frame, err := stream.Recv()
		require.NoError(t, err, "watch sweep delivers a cross-replica command within the watch interval")
		cmd := frame.GetCommand()
		require.NotNil(t, cmd)
		assert.Equal(t, int64(11), cmd.GetId())
		assert.Equal(t, "isolate_host", cmd.GetCommandType())
		assert.Equal(t, "host-a", cmd.GetHostId())
		assert.JSONEq(t, `{"mode":"full"}`, string(cmd.GetPayload()))
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

// TestGatewayWatchIntervalIsCompiledConstant pins the server-configuration invariant that the control-channel command-watch interval is a
// fixed compiled constant, not an operator knob. The inertness is structural: the gateway constructor takes only resolved Deps and reads
// no environment variable, so there is no EDR_*WATCH* override seam, and New always seeds the effective watch interval from the compiled
// defaultWatchInterval. (The repo forbids mutating process env in tests and resolves configuration at the boundary, issue #172, so the
// honest assertion here is that New has no env-derived interval to override.)
// spec:server-configuration/the-server-configuration-surface-is-intentionally-minimal/the-command-watch-interval-is-not-an-operator-knob
func TestGatewayWatchIntervalIsCompiledConstant(t *testing.T) {
	t.Parallel()

	g := New(Deps{Source: newFakeSource(), Verifier: newFakeVerifier()})

	assert.Equal(t, defaultWatchInterval, g.watchInterval, "the command-watch interval is compiled, not an operator knob")
	assert.Equal(t, time.Second, g.watchInterval, "the compiled watch interval is one second")
}

// A heartbeat must never displace a queued command, and must never block the connection's maintenance loop.
//
// The send buffer is bounded, so the interesting case is what happens when it is full. Dropping the heartbeat is correct there and not
// merely convenient: a full buffer already proves frames are flowing to this agent, which is the very thing a heartbeat exists to
// demonstrate, while a heartbeat that displaced a command would trade a diagnostic for a response action (issue #711).
func TestHeartbeatIsDroppedRatherThanDisplacingAQueuedCommand(t *testing.T) {
	t.Parallel()
	g := New(Deps{Source: newFakeSource(), Verifier: newFakeVerifier()})
	g.livenessInterval = time.Millisecond

	c := newConn("host-full", "tok", func() {})
	// Fill the outbound queue with commands, so any heartbeat has nowhere to go.
	for i := range sendBuffer {
		require.True(t, c.push(&control.ServerFrame{
			Frame: &control.ServerFrame_Command{Command: &control.Command{Id: int64(i + 1), HostId: "host-full"}},
		}), "the buffer should accept exactly sendBuffer frames")
	}
	require.Len(t, c.send, sendBuffer)

	// maintain must return on context cancellation rather than blocking on the full queue.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); g.maintain(ctx, c) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("maintain blocked on a full send buffer instead of dropping the heartbeat")
	}

	// Every queued frame is still a command: no heartbeat evicted one, and none was appended.
	require.Len(t, c.send, sendBuffer)
	for range sendBuffer {
		frame := <-c.send
		require.NotNil(t, frame.GetCommand(), "a queued command must not have been displaced by a heartbeat")
	}
}
