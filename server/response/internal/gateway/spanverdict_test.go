package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	otelcodes "go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/fleetdm/edr/internal/control"
)

// What an operator actually sees about a control connection is its span, and these tests read the recorded span rather than the
// handler's return value (issue #1124).
//
// The distinction is the whole reason this file exists. A client that goes away takes the transport with it, and gRPC ends the RPC
// with the transport's own error whatever the handler returned, so a handler that returns nil is NOT sufficient to record an
// ordinary disconnect as successful. The first version of this fix changed only the handler, passed its unit tests, and still
// produced `Error: transport is closing` on edr-dev.
//
// So the gateway is served here the way production serves it, over net/http's HTTP/2 server rather than bufconn, and the client's
// socket is killed rather than closed politely. Both details matter: they are what reproduces the failure.

// recordedConn is one client connection to a recorded gateway: the stream, and the raw socket underneath it so a test can make the
// client vanish the way a killed agent does.
type recordedConn struct {
	stream control.ControlChannel_ConnectClient
	socket net.Conn
}

// recordedGateway serves a gateway over cleartext HTTP/2 with an in-memory span recorder, and returns the recorder, the gateway,
// and a dialer.
func recordedGateway(t *testing.T, ver *fakeVerifier) (*tracetest.SpanRecorder, *Gateway, func(token string) recordedConn) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	// The gateway's OWN server, with only the tracer provider substituted. Building a server here instead would leave New's wrapping
	// untested, and New's wrapping is the fix.
	g := New(Deps{
		Source:   newFakeSource(),
		Verifier: ver,
		Stats:    otelgrpc.NewServerHandler(otelgrpc.WithTracerProvider(provider)),
	})
	g.livenessInterval = 20 * time.Millisecond
	g.revocationInterval = 20 * time.Millisecond
	srv := g.GRPCServer()

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	httpSrv := &http.Server{Handler: srv, Protocols: protocols, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(lis) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	dial := func(token string) recordedConn {
		t.Helper()
		var socket net.Conn
		cc, err := grpc.NewClient(lis.Addr().String(),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				c, derr := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				socket = c
				return c, derr
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = cc.Close() })
		stream, err := control.NewControlChannelClient(cc).Connect(connectCtx(token))
		require.NoError(t, err)
		return recordedConn{stream: stream, socket: socket}
	}
	return recorder, g, dial
}

// connectStatus waits for the Connect span to be recorded and returns the status it carries, which is the whole of what an operator
// reads about how that connection ended.
func connectStatus(t *testing.T, recorder *tracetest.SpanRecorder) sdktrace.Status {
	t.Helper()
	var recorded sdktrace.Status
	require.Eventually(t, func() bool {
		for _, s := range recorder.Ended() {
			if s.Name() == "fleetedr.control.v1.ControlChannel/Connect" {
				recorded = s.Status()
				return true
			}
		}
		return false
	}, 10*time.Second, 20*time.Millisecond, "the connection's span was never recorded")
	return recorded
}

// The headline. Every host disconnects routinely, so recording each as a failure left this operation permanently error-coloured and
// a genuine control-path fault indistinguishable from the background.
//
// spec:agent-control-channel/how-a-connection-ended-is-what-its-telemetry-reports/a-client-that-disconnects-ends-its-connection-cleanly
func TestAnOrdinaryDisconnectIsNotRecordedAsAFailedConnection(t *testing.T) {
	t.Parallel()
	ver := newFakeVerifier()
	ver.add("tok-a", "host-a")
	recorder, g, dial := recordedGateway(t, ver)

	conn := dial("tok-a")
	require.Eventually(t, func() bool { return g.reg.get("host-a") != nil }, 5*time.Second, 10*time.Millisecond)

	// Killed, not closed: a restarted or suspended agent does not get to send a GOAWAY, and a polite close does not reproduce this.
	require.NoError(t, conn.socket.Close())

	recorded := connectStatus(t, recorder)
	assert.NotEqual(t, otelcodes.Error, recorded.Code,
		"an agent restart, a closed lid or a dropped link is how a control connection ordinarily ends")
	assert.Empty(t, recorded.Description)
}

// The other half: the wrapper must not swallow the connections an operator is looking for. A teardown the server initiated is one
// of those, and its span has to name which teardown it was.
//
// spec:agent-control-channel/how-a-connection-ended-is-what-its-telemetry-reports/a-server-teardown-still-tells-the-client-to-reconnect
func TestAServerTeardownIsStillRecordedAsAFailedConnection(t *testing.T) {
	t.Parallel()
	ver := newFakeVerifier()
	ver.add("tok-a", "host-a")
	recorder, g, dial := recordedGateway(t, ver)

	dial("tok-a")
	require.Eventually(t, func() bool { return g.reg.get("host-a") != nil }, 5*time.Second, 10*time.Millisecond)

	ver.revoke("tok-a") // the maintenance re-check tears the connection down

	recorded := connectStatus(t, recorder)
	assert.Equal(t, otelcodes.Error, recorded.Code, "a connection the server ended is the case an operator wants to find")
	assert.Contains(t, recorded.Description, string(reasonTokenInvalid))
}

// recordingStats captures the events the wrapper forwards, so a test can see what the OTel handler underneath would have been given.
type recordingStats struct {
	stats.Handler
	ends chan *stats.End
}

func newRecordingStats() *recordingStats {
	return &recordingStats{Handler: otelgrpc.NewServerHandler(), ends: make(chan *stats.End, 4)}
}

func (r *recordingStats) HandleRPC(ctx context.Context, rpcStats stats.RPCStats) {
	if end, ok := rpcStats.(*stats.End); ok {
		r.ends <- end
	}
	r.Handler.HandleRPC(ctx, rpcStats)
}

// The fail-safe. A verdict is only ever recorded by a handler that ran to completion, so an RPC that never reported one keeps
// whatever gRPC said about it, rather than being quietly recoloured by a wrapper that read silence as success. An RPC the auth
// interceptor refuses is the case that reaches this: its handler never runs.
func TestAnRPCThatReportedNoVerdictKeepsItsFailure(t *testing.T) {
	t.Parallel()
	inner := newRecordingStats()
	wrapped := handlerVerdictStats{Handler: inner}
	ctx := wrapped.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: "/fleetedr.control.v1.ControlChannel/Connect"})
	refused := status.Error(codes.Unauthenticated, "invalid host token")

	wrapped.HandleRPC(ctx, &stats.End{Error: refused})

	forwarded := <-inner.ends
	assert.Equal(t, refused, forwarded.Error, "nothing recorded a verdict for this RPC, so its failure stands")
}

// And the converse, which is the fix itself: an RPC whose handler reported success is forwarded with no error, so the span records
// the verdict rather than the transport's account of how the stream ended.
func TestAnRPCWhoseHandlerSucceededIsForwardedWithoutTheTransportError(t *testing.T) {
	t.Parallel()
	inner := newRecordingStats()
	wrapped := handlerVerdictStats{Handler: inner}
	ctx := wrapped.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: "/fleetedr.control.v1.ControlChannel/Connect"})
	recordSpanVerdict(ctx, nil)

	transportDied := errors.New("transport is closing")
	original := &stats.End{Error: transportDied}
	wrapped.HandleRPC(ctx, original)

	forwarded := <-inner.ends
	require.NoError(t, forwarded.Error)
	assert.Equal(t, transportDied, original.Error, "the event belongs to gRPC: it is copied, never mutated")
}

// TagRPC has to attach the verdict where the End event can find it: on the context gRPC threads through the RPC. Pinned directly
// because the wrapper silently degrades to a passthrough if it does not, which would look exactly like the bug it fixes.
func TestTheVerdictRidesTheContextTheEndEventCarries(t *testing.T) {
	t.Parallel()
	wrapped := handlerVerdictStats{Handler: otelgrpc.NewServerHandler()}

	ctx := wrapped.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: "/fleetedr.control.v1.ControlChannel/Connect"})

	verdict, ok := ctx.Value(spanVerdictKey{}).(*spanVerdict)
	require.True(t, ok, "without this the wrapper is an expensive passthrough")
	assert.False(t, verdict.succeeded.Load(), "a verdict starts unrecorded, so an RPC that never reports one keeps its failure")

	recordSpanVerdict(ctx, nil)
	assert.True(t, verdict.succeeded.Load())
	recordSpanVerdict(ctx, assert.AnError)
	assert.False(t, verdict.succeeded.Load(), "a handler that failed says so, even after an earlier success on the same RPC")
}

// A context with no verdict on it must not panic the handler: the value is absent for any RPC this gateway did not tag.
func TestRecordingAVerdictOnAnUntaggedContextIsInert(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() { recordSpanVerdict(context.Background(), nil) })
}
