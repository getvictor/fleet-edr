package controlclient_test

import (
	"context"
	"net"
	"sync"
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
	push      []*control.Command
	failFirst bool

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

// startClient wires a fakeGateway over bufconn and runs a control client against it until the test ends.
func startClient(t *testing.T, fake *fakeGateway, sender *recordingSender) (*fakeGateway, func() bool) {
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
	var mu sync.Mutex
	client := controlclient.New(controlclient.Config{
		Client:                   control.NewControlChannelClient(cc),
		HostID:                   "host-a",
		TokenFn:                  func() string { return "tok" },
		ApplicationControlSender: sender,
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
	isConnected := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return connected
	}
	return fake, isConnected
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
		_, isConnected := startClient(t, fake, sender)

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
}
