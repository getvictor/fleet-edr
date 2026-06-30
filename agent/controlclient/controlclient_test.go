package controlclient_test

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/fleetdm/edr/agent/controlclient"
	"github.com/fleetdm/edr/internal/control"
)

// fakeGateway is an in-memory control gateway: it pushes a fixed set of commands on connect and records every outcome the agent
// reports back.
type fakeGateway struct {
	control.UnimplementedControlChannelServer
	push          []*control.Command
	failFirst     bool
	authFailFirst bool

	mu       sync.Mutex
	attempts int
	outcomes []*control.Outcome
}

func (g *fakeGateway) Connect(stream control.ControlChannel_ConnectServer) error {
	g.mu.Lock()
	g.attempts++
	first := g.attempts == 1
	g.mu.Unlock()
	if first && g.failFirst {
		return status.Error(codes.Unavailable, "transient failure") // forces the client to back off and reconnect
	}
	if first && g.authFailFirst {
		return status.Error(codes.Unauthenticated, "bad token") // forces the client to re-enroll, then reconnect
	}
	for _, cmd := range g.push {
		if err := stream.Send(&control.ServerFrame{Frame: &control.ServerFrame_Command{Command: cmd}}); err != nil {
			return err
		}
	}
	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		if oc := frame.GetOutcome(); oc != nil {
			g.mu.Lock()
			g.outcomes = append(g.outcomes, oc)
			g.mu.Unlock()
		}
	}
}

func (g *fakeGateway) recorded() []*control.Outcome {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]*control.Outcome(nil), g.outcomes...)
}

// recordingSender captures application-control payloads so the test sees how many times a command's side effect ran, without cgo/XPC.
type recordingSender struct {
	mu   sync.Mutex
	sent [][]byte
}

func (r *recordingSender) SendApplicationControl(payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, append([]byte(nil), payload...))
	return nil
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

// startClient wires a fakeGateway over bufconn and runs a control client against it until the test ends. It returns a connected
// predicate and an auth-failure counter so tests can observe re-enrollment without standing up a real token provider.
func startClient(t *testing.T, fake *fakeGateway, sender *recordingSender) (isConnected func() bool, authFails func() int) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	control.RegisterControlChannelServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	var connected bool
	var authFailCount int
	var mu sync.Mutex
	client := controlclient.New(controlclient.Config{
		Client:                   control.NewControlChannelClient(cc),
		HostID:                   "host-a",
		TokenFn:                  func() string { return "tok" },
		ApplicationControlSender: sender,
		OnAuthFail: func(context.Context) {
			mu.Lock()
			authFailCount++
			mu.Unlock()
		},
		OnConnectedChange: func(v bool) {
			mu.Lock()
			connected = v
			mu.Unlock()
		},
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(t.Context())
	go func() { _ = client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		srv.Stop()
		_ = cc.Close()
	})
	isConnected = func() bool {
		mu.Lock()
		defer mu.Unlock()
		return connected
	}
	authFails = func() int {
		mu.Lock()
		defer mu.Unlock()
		return authFailCount
	}
	return isConnected, authFails
}

const appControlPayload = `{"policy_id":7,"policy_version":1,"rules":[]}`

func TestControlClient(t *testing.T) {
	t.Parallel()

	t.Run("pushed command is executed and its outcome reported", func(t *testing.T) {
		t.Parallel()
		fake := &fakeGateway{push: []*control.Command{
			{Id: 7, HostId: "host-a", CommandType: "set_application_control", Payload: []byte(appControlPayload)},
		}}
		sender := &recordingSender{}
		isConnected, _ := startClient(t, fake, sender)

		require.Eventually(t, isConnected, 2*time.Second, 10*time.Millisecond)
		require.Eventually(t, func() bool { return len(fake.recorded()) >= 2 }, 2*time.Second, 10*time.Millisecond)

		assert.Equal(t, 1, sender.count(), "the command's side effect runs exactly once")
		outs := fake.recorded()
		require.GreaterOrEqual(t, len(outs), 2)
		assert.Equal(t, "acked", outs[0].GetStatus())
		assert.Equal(t, "completed", outs[1].GetStatus())
		assert.Equal(t, int64(7), outs[0].GetId())
	})

	t.Run("re-delivered command re-reports its outcome without re-executing", func(t *testing.T) {
		t.Parallel()
		// The gateway pushes the same command id twice (the lost-ack / reconnect re-delivery case).
		cmd := &control.Command{Id: 9, HostId: "host-a", CommandType: "set_application_control", Payload: []byte(appControlPayload)}
		fake := &fakeGateway{push: []*control.Command{cmd, cmd}}
		sender := &recordingSender{}
		_, _ = startClient(t, fake, sender)

		// Both deliveries report acked+completed (4 outcomes), but the side effect runs only once.
		require.Eventually(t, func() bool { return len(fake.recorded()) >= 4 }, 2*time.Second, 10*time.Millisecond)
		assert.Equal(t, 1, sender.count(), "a re-delivered command must not run its side effect again")
		for _, oc := range fake.recorded() {
			assert.Equal(t, int64(9), oc.GetId())
		}
	})

	t.Run("reconnects with backoff after a dropped stream", func(t *testing.T) {
		t.Parallel()
		// The gateway fails the first stream; the client must back off and reconnect, then receive and execute the pushed command.
		fake := &fakeGateway{
			failFirst: true,
			push:      []*control.Command{{Id: 5, HostId: "host-a", CommandType: "set_application_control", Payload: []byte(appControlPayload)}},
		}
		sender := &recordingSender{}
		_, _ = startClient(t, fake, sender)

		require.Eventually(t, func() bool { return len(fake.recorded()) >= 2 }, 3*time.Second, 10*time.Millisecond)
		assert.Equal(t, 1, sender.count())
	})

	t.Run("unknown command type fails explicitly", func(t *testing.T) {
		t.Parallel()
		fake := &fakeGateway{push: []*control.Command{
			{Id: 3, HostId: "host-a", CommandType: "reboot", Payload: []byte(`{}`)},
		}}
		_, _ = startClient(t, fake, &recordingSender{})
		require.Eventually(t, func() bool { return len(fake.recorded()) >= 2 }, 2*time.Second, 10*time.Millisecond)
		outs := fake.recorded()
		assert.Equal(t, "acked", outs[0].GetStatus())
		assert.Equal(t, "failed", outs[1].GetStatus())
		assert.Contains(t, string(outs[1].GetResult()), "unknown command type")
	})

	t.Run("command addressed to a different host is dropped without executing", func(t *testing.T) {
		t.Parallel()
		// The first command targets another host (a server routing bug); it must not run and must not report any outcome, since
		// that outcome would carry an id belonging to host-b. The second, correctly addressed, command still executes so the
		// stream is proven live.
		fake := &fakeGateway{push: []*control.Command{
			{Id: 100, HostId: "host-b", CommandType: "set_application_control", Payload: []byte(appControlPayload)},
			{Id: 101, HostId: "host-a", CommandType: "set_application_control", Payload: []byte(appControlPayload)},
		}}
		sender := &recordingSender{}
		_, _ = startClient(t, fake, sender)

		// Wait until the correctly addressed command has driven acked+completed.
		require.Eventually(t, func() bool { return len(fake.recorded()) >= 2 }, 2*time.Second, 10*time.Millisecond)
		assert.Equal(t, 1, sender.count(), "only the correctly addressed command runs its side effect")
		for _, oc := range fake.recorded() {
			assert.Equal(t, int64(101), oc.GetId(), "no outcome is ever reported for the misrouted command")
		}
	})

	t.Run("auth rejection on connect drives re-enrollment then recovers", func(t *testing.T) {
		t.Parallel()
		// The gateway rejects the first stream as Unauthenticated. The client must invoke OnAuthFail (re-enrollment) and, crucially,
		// must NOT reset its backoff for an auth-rejected session, then reconnect and execute the pushed command.
		fake := &fakeGateway{
			authFailFirst: true,
			push:          []*control.Command{{Id: 12, HostId: "host-a", CommandType: "set_application_control", Payload: []byte(appControlPayload)}},
		}
		sender := &recordingSender{}
		_, authFails := startClient(t, fake, sender)

		require.Eventually(t, func() bool { return authFails() >= 1 }, 2*time.Second, 10*time.Millisecond)
		require.Eventually(t, func() bool { return sender.count() == 1 }, 3*time.Second, 10*time.Millisecond)
	})
}

// connectErrClient is a control.ControlChannelClient whose Connect fails before any stream exists, exercising the runStream path that
// inspects the Connect() error (rather than the first Recv) for an Unauthenticated rejection.
type connectErrClient struct {
	err error
	mu  sync.Mutex
	n   int
}

func (c *connectErrClient) Connect(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[control.AgentFrame, control.ServerFrame], error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil, c.err
}

func (c *connectErrClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestControlClientAuthFailOnConnect(t *testing.T) {
	t.Parallel()
	// When the gateway rejects the RPC during Connect() (the auth interceptor can deny before the stream opens), the client must
	// still treat it as an auth failure and trigger re-enrollment, not silently retry forever.
	stub := &connectErrClient{err: status.Error(codes.Unauthenticated, "denied at setup")}
	var authFails atomic.Int32
	client := controlclient.New(controlclient.Config{
		Client:         stub,
		HostID:         "host-a",
		TokenFn:        func() string { return "tok" },
		OnAuthFail:     func(context.Context) { authFails.Add(1) },
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     30 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = client.Run(ctx) }()

	require.Eventually(t, func() bool { return authFails.Load() >= 1 }, 2*time.Second, 5*time.Millisecond)
	assert.GreaterOrEqual(t, stub.calls(), 1)
}

// scriptedStream is a client bidi stream whose Send always fails (a one-way-broken stream) and whose Recv yields a queued command
// then blocks until ctx ends. It exercises the runStream path that reconnects when handleCommand cannot report an outcome.
type scriptedStream struct {
	grpc.ClientStream
	ctx     context.Context
	mu      sync.Mutex
	recvQ   []*control.ServerFrame
	sendErr error
}

func (s *scriptedStream) Send(*control.AgentFrame) error { return s.sendErr }

func (s *scriptedStream) Recv() (*control.ServerFrame, error) {
	s.mu.Lock()
	if len(s.recvQ) > 0 {
		f := s.recvQ[0]
		s.recvQ = s.recvQ[1:]
		s.mu.Unlock()
		return f, nil
	}
	s.mu.Unlock()
	<-s.ctx.Done()
	return nil, io.EOF
}

// scriptedClient hands out a failing-Send stream on the first connect (carrying one command) and inert streams afterwards, so a
// reconnect is observable without spinning.
type scriptedClient struct {
	cmd      *control.Command
	sendErr  error
	mu       sync.Mutex
	connects int
}

func (c *scriptedClient) Connect(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[control.AgentFrame, control.ServerFrame], error) {
	c.mu.Lock()
	c.connects++
	first := c.connects == 1
	c.mu.Unlock()
	st := &scriptedStream{ctx: ctx}
	if first {
		st.recvQ = []*control.ServerFrame{{Frame: &control.ServerFrame_Command{Command: c.cmd}}}
		st.sendErr = c.sendErr
	}
	return st, nil
}

func (c *scriptedClient) connectCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connects
}

func TestControlClientReconnectsOnSendFailure(t *testing.T) {
	t.Parallel()
	// The first stream delivers a command but every Send fails (one-way-broken stream). handleCommand must surface that error so
	// runStream tears the stream down and reconnects, rather than sitting "connected" while silently dropping outcomes.
	stub := &scriptedClient{
		cmd:     &control.Command{Id: 21, HostId: "host-a", CommandType: "set_application_control", Payload: []byte(appControlPayload)},
		sendErr: status.Error(codes.Unavailable, "broken send"),
	}
	client := controlclient.New(controlclient.Config{
		Client:                   stub,
		HostID:                   "host-a",
		TokenFn:                  func() string { return "tok" },
		ApplicationControlSender: &recordingSender{},
		InitialBackoff:           5 * time.Millisecond,
		MaxBackoff:               20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = client.Run(ctx) }()

	// A reconnect (connects >= 2) proves the send failure tore the stream down rather than wedging it.
	require.Eventually(t, func() bool { return stub.connectCount() >= 2 }, 2*time.Second, 5*time.Millisecond)
}
