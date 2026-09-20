package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/fleetdm/edr/internal/control"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
)

// These tests call the Connect handler directly rather than over bufconn, because what they pin is the value it returns. That value
// is what the gRPC layer turns into the RPC's status, and what otelgrpc's stats handler then records as the span's status, so it is
// the whole of what an operator sees about how a connection ended (issue #1124). Over a real transport it is unobservable in exactly
// the case that matters, where the client has already gone.

// fakeStream is a server stream whose RPC context, receive result and send outcome the test controls.
type fakeStream struct {
	grpc.ServerStream // unused on this path: Connect touches only Context, Recv and Send
	ctx               context.Context
	recvErr           chan error
	sendErr           error
	sent              chan *control.ServerFrame
}

// newFakeStream builds a stream carrying what the auth interceptor pins in production: the host id and the token it verified.
func newFakeStream(ctx context.Context, hostID, token string) *fakeStream {
	return &fakeStream{
		ctx:     context.WithValue(endpointapi.WithHostID(ctx, hostID), tokenKey, token),
		recvErr: make(chan error, 1),
		sent:    make(chan *control.ServerFrame, sendBuffer),
	}
}

func (s *fakeStream) Context() context.Context { return s.ctx }

// Send drops a frame nothing is reading rather than blocking the writer: heartbeats tick on their own here and are not what any of
// these tests assert.
func (s *fakeStream) Send(frame *control.ServerFrame) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	select {
	case s.sent <- frame:
	default:
	}
	return nil
}

// Recv blocks until the peer says something or the RPC ends, like the real one, so the handler's two ends race as they do in
// production: a client that goes away cancels the context AND fails the pending receive.
func (s *fakeStream) Recv() (*control.AgentFrame, error) {
	select {
	case err := <-s.recvErr:
		return nil, err
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

// connectedGateway starts Connect for one host against a fake stream and returns the gateway and a channel carrying what the handler
// returned, once the connection is registered.
func connectedGateway(t *testing.T, stream *fakeStream) (*Gateway, <-chan error) {
	t.Helper()
	ver := newFakeVerifier()
	ver.add("tok-a", "host-a")
	g := New(Deps{Source: newFakeSource(), Verifier: ver})
	g.livenessInterval = 20 * time.Millisecond
	g.revocationInterval = 20 * time.Millisecond

	returned := make(chan error, 1)
	go func() { returned <- g.Connect(stream) }()
	require.Eventually(t, func() bool { return g.reg.get("host-a") != nil }, 2*time.Second, 10*time.Millisecond)
	return g, returned
}

// returnedFrom waits for the handler to return, bounded so a handler that never does fails the test instead of hanging the suite.
func returnedFrom(t *testing.T, returned <-chan error) error {
	t.Helper()
	select {
	case err := <-returned:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("the Connect handler never returned")
		return nil
	}
}

// requireTornDownBecause asserts the handler ended the RPC the way a server-initiated teardown must: retryably, so the client
// reconnects, and naming which teardown it was.
func requireTornDownBecause(t *testing.T, returned <-chan error, reason closeReason) {
	t.Helper()
	err := returnedFrom(t, returned)
	require.Error(t, err, "a client that is still attached has to be told to reconnect")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), string(reason),
		"an operator asking why this host's channel dropped can only read the answer here")
}

// An agent restart, a closed lid, a dropped link: the ordinary end of a long-lived control connection, and the overwhelming majority
// of them. Recording each as a failure left the operation permanently error-coloured, so a real fault on the control path was
// indistinguishable from the background (issue #1124).
//
// spec:agent-control-channel/how-a-connection-ended-is-what-its-telemetry-reports/a-client-that-disconnects-ends-its-connection-cleanly
func TestConnectEndsCleanlyWhenTheClientWentAway(t *testing.T) {
	t.Parallel()
	ctx, clientGoesAway := context.WithCancel(t.Context())
	stream := newFakeStream(ctx, "host-a", "tok-a")
	g, returned := connectedGateway(t, stream)

	clientGoesAway()

	require.NoError(t, returnedFrom(t, returned), "an ordinary disconnect must not be recorded as a failed connection")
	assert.Nil(t, g.reg.get("host-a"), "and the connection is still deregistered")
}

// Each of these is a different operational story, and each is reached through the path that actually produces it rather than by
// setting the reason directly: what matters is that the connection carries the right one when the server ends it.
//
// spec:agent-control-channel/how-a-connection-ended-is-what-its-telemetry-reports/a-server-teardown-still-tells-the-client-to-reconnect
func TestConnectReportsWhyTheServerToreTheConnectionDown(t *testing.T) {
	t.Parallel()

	t.Run("replaced by a reconnect from the same host", func(t *testing.T) {
		t.Parallel()
		first := newFakeStream(t.Context(), "host-a", "tok-a")
		g, returned := connectedGateway(t, first)

		second := newFakeStream(t.Context(), "host-a", "tok-a")
		go func() { _ = g.Connect(second) }()

		requireTornDownBecause(t, returned, reasonReplaced)
	})

	t.Run("the host token is no longer valid", func(t *testing.T) {
		t.Parallel()
		stream := newFakeStream(t.Context(), "host-a", "tok-a")
		g, returned := connectedGateway(t, stream)

		g.verifier.(*fakeVerifier).revoke("tok-a")

		requireTornDownBecause(t, returned, reasonTokenInvalid)
	})

	t.Run("the gateway is shutting down", func(t *testing.T) {
		t.Parallel()
		stream := newFakeStream(t.Context(), "host-a", "tok-a")
		g, returned := connectedGateway(t, stream)

		g.Stop()

		requireTornDownBecause(t, returned, reasonShuttingDown)
	})

	t.Run("the outbound can no longer carry frames", func(t *testing.T) {
		t.Parallel()
		// Set before connecting, so the first heartbeat the maintenance loop pushes fails the send.
		stream := newFakeStream(t.Context(), "host-a", "tok-a")
		stream.sendErr = errors.New("broken pipe")
		_, returned := connectedGateway(t, stream)

		requireTornDownBecause(t, returned, reasonSendFailed)
	})
}

// A stream that fails under a client that is still there is the case this whole change exists to keep visible.
//
// spec:agent-control-channel/how-a-connection-ended-is-what-its-telemetry-reports/a-receive-failure-is-still-recorded-as-a-failure
func TestConnectReportsAReceiveFailureWhileTheClientIsAttached(t *testing.T) {
	t.Parallel()
	stream := newFakeStream(t.Context(), "host-a", "tok-a")
	_, returned := connectedGateway(t, stream)

	brokenStream := errors.New("stream failed")
	stream.recvErr <- brokenStream

	require.ErrorIs(t, returnedFrom(t, returned), brokenStream)
}

// closedConn is a connection the server has torn down for the given reason, with no live stream behind it.
func closedConn(t *testing.T, reason closeReason) *conn {
	t.Helper()
	_, cancel := context.WithCancel(t.Context())
	c := newConn("host-a", "tok-a", cancel)
	c.close(reason)
	return c
}

func TestEndAfterTeardown(t *testing.T) {
	t.Parallel()

	t.Run("the client is already gone, so there is nobody to return a status to", func(t *testing.T) {
		t.Parallel()
		gone, cancel := context.WithCancel(t.Context())
		cancel()

		// Even though something here also closed the connection: the client leaving is what ended it, and a teardown racing the
		// disconnect is a consequence of it, not a fault to report.
		assert.NoError(t, endAfterTeardown(gone, closedConn(t, reasonSendFailed)))
	})

	for _, reason := range []closeReason{reasonReplaced, reasonTokenInvalid, reasonShuttingDown, reasonSendFailed} {
		t.Run("the server ended it: "+string(reason), func(t *testing.T) {
			t.Parallel()
			err := endAfterTeardown(t.Context(), closedConn(t, reason))

			require.Error(t, err)
			assert.Equal(t, codes.Unavailable, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), string(reason))
		})
	}
}

func TestEndAfterReceive(t *testing.T) {
	t.Parallel()
	failed := errors.New("stream failed")

	t.Run("a failure under an attached client is the failure", func(t *testing.T) {
		t.Parallel()
		assert.ErrorIs(t, endAfterReceive(t.Context(), failed), failed)
	})

	// The same failure, once the client has gone, IS the disconnect: cancelling the RPC context is what made the pending receive
	// fail. Both select cases have to reach this verdict, or which one the scheduler picks would decide the span's status.
	t.Run("the same failure once the client has gone is the disconnect", func(t *testing.T) {
		t.Parallel()
		gone, cancel := context.WithCancel(t.Context())
		cancel()

		assert.NoError(t, endAfterReceive(gone, failed))
	})

	// A client half-close reaches here as no error at all, and has always ended the RPC cleanly.
	t.Run("an end of stream with no failure stays clean", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, endAfterReceive(t.Context(), nil))
	})
}
