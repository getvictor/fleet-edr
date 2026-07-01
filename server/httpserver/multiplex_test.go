package httpserver_test

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/fleetdm/edr/server/httpserver"
)

// grpcControlMux adapts a *grpc.Server to httpserver.ControlMux for the multiplex test: ServeHTTP is the gRPC-over-HTTP/2 handler and
// Stop force-stops the server. GracefulStop is avoided deliberately: it panics ("Drain is not implemented") once the server has served
// via grpc.Server.ServeHTTP, which is the production path here; the real gateway's Stop likewise ends streams rather than GracefulStop.
type grpcControlMux struct{ s *grpc.Server }

func (g grpcControlMux) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.s.ServeHTTP(w, r) }

func (g grpcControlMux) Stop() { g.s.Stop() }

func waitListening(t *testing.T, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 3*time.Second, 20*time.Millisecond, "server never started listening on %s", addr)
}

// TestRunAndShutdown_MultiplexesGRPCAndHTTP pins the shared-port design (issue #477): the agent control-channel gRPC gateway and the
// REST/UI HTTP surface are served on ONE listener, separated by content-type. It asserts that a gRPC call (HTTP/2,
// application/grpc) and HTTP requests over both HTTP/1.1 and HTTP/2 all succeed on the same address, in both the server-terminates-TLS
// and the plaintext (proxy-terminated) modes, and that a ctx cancel still drives a clean shutdown.
//
// spec:server-configuration/the-agent-control-channel-shares-the-main-server-listener/grpc-and-rest-share-one-port
func TestRunAndShutdown_MultiplexesGRPCAndHTTP(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		useTLS bool
	}{
		{"server terminates TLS", true},
		{"plaintext (proxy-terminated)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := freeAddr(t)

			mux := http.NewServeMux()
			mux.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
				// Echo the protocol so the test can assert HTTP/2 REST was served (not misrouted to the gRPC server).
				_, _ = io.WriteString(w, r.Proto) //nolint:gosec // G705: r.Proto is the negotiated protocol string, not user-controlled input
			})
			srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			if tc.useTLS {
				srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSignedTLS(t)}, MinVersion: tls.VersionTLS12}
			}

			grpcSrv := grpc.NewServer()
			hs := health.NewServer()
			hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
			healthpb.RegisterHealthServer(grpcSrv, hs)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- httpserver.RunAndShutdown(ctx, srv, grpcControlMux{s: grpcSrv}, slog.Default(), nil, 0)
			}()
			waitListening(t, addr)

			scheme := "http"
			var grpcCreds credentials.TransportCredentials
			if tc.useTLS {
				scheme = "https"
				grpcCreds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // in-test self-signed cert
			} else {
				grpcCreds = insecure.NewCredentials()
			}

			// gRPC over HTTP/2 (content-type application/grpc) must reach the gRPC server.
			cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(grpcCreds))
			require.NoError(t, err)
			defer func() { _ = cc.Close() }()
			callCtx, callCancel := context.WithTimeout(ctx, 3*time.Second)
			defer callCancel()
			resp, err := healthpb.NewHealthClient(cc).Check(callCtx, &healthpb.HealthCheckRequest{})
			require.NoError(t, err, "gRPC health check on the shared port")
			assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

			// HTTP/1.1 REST on the same port must reach the HTTP server.
			body, proto := httpGet(t, h1Client(tc.useTLS), scheme+"://"+addr+"/ping")
			assert.Equal(t, "HTTP/1.1", body, "HTTP/1.1 request body echoes its own proto")
			assert.Equal(t, "HTTP/1.1", proto)

			// HTTP/2 REST (NOT application/grpc) must reach the HTTP server, not be swallowed by the gRPC matcher. Reuse ONE client
			// (one pooled HTTP/2 connection) across multiple requests, the way a real Go agent does: the multiplexer must not corrupt
			// the persistent connection after the first request.
			restClient := h2Client(t, tc.useTLS, addr)
			for req := range 3 {
				h2body, proto := httpGet(t, restClient, scheme+"://"+addr+"/ping")
				assert.Equal(t, "HTTP/2.0", h2body, "request %d: HTTP/2 REST is multiplexed to the HTTP server", req)
				assert.Equal(t, "HTTP/2.0", proto, "request %d stays on HTTP/2 over the reused connection", req)
			}

			cancel()
			select {
			case err := <-done:
				require.NoError(t, err, "graceful shutdown returns nil")
			case <-time.After(httpserver.ShutdownTimeout + 2*time.Second):
				t.Fatal("RunAndShutdown did not return after ctx cancel")
			}
		})
	}
}

// TestRunAndShutdown_ControlStreamOutlivesServerTimeouts is a regression for the single-port control channel (issue #477): the shared
// http.Server's ReadTimeout/WriteTimeout bound a whole HTTP/2 stream, so leaving them in force would tear the long-lived agent control
// stream down on that cadence (a 10s read timeout in production, observed as a ~10s reconnect flap in live QA) rather than holding one
// connection. mountControlChannel must clear both per-stream deadlines for the application/grpc branch, while REST keeps the timeouts. A
// server-streaming health Watch stands in for the control stream: it is held open well past the server's Read/Write timeouts and must
// still deliver a later status change.
//
// spec:server-configuration/the-agent-control-channel-shares-the-main-server-listener/control-stream-not-bounded-by-rest-timeouts
func TestRunAndShutdown_ControlStreamOutlivesServerTimeouts(t *testing.T) {
	t.Parallel()
	addr := freeAddr(t)
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: 5 * time.Second,
		// Deliberately short: without the deadline clear in mountControlChannel the http2 server tears the stream down at ~250ms.
		ReadTimeout:  250 * time.Millisecond,
		WriteTimeout: 250 * time.Millisecond,
	}

	grpcSrv := grpc.NewServer()
	hs := health.NewServer()
	hs.SetServingStatus("svc", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, hs)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- httpserver.RunAndShutdown(ctx, srv, grpcControlMux{s: grpcSrv}, slog.Default(), nil, 0)
	}()
	waitListening(t, addr)

	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	streamCtx, streamCancel := context.WithTimeout(ctx, 5*time.Second)
	defer streamCancel()
	watch, err := healthpb.NewHealthClient(cc).Watch(streamCtx, &healthpb.HealthCheckRequest{Service: "svc"})
	require.NoError(t, err)
	first, err := watch.Recv()
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, first.GetStatus())

	// Hold the stream idle well past the server's 250ms Read/Write timeouts, then push a status change over it. Without the fix the stream
	// is already dead and this Recv errors; with the fix the stream is still up and delivers the change.
	time.Sleep(1 * time.Second)
	hs.SetServingStatus("svc", healthpb.HealthCheckResponse_NOT_SERVING)
	second, err := watch.Recv()
	require.NoError(t, err, "control-style stream must outlive the REST server's Read/Write timeouts")
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, second.GetStatus())

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "graceful shutdown returns nil")
	case <-time.After(httpserver.ShutdownTimeout + 2*time.Second):
		t.Fatal("RunAndShutdown did not return after ctx cancel")
	}
}

func httpGet(t *testing.T, c *http.Client, url string) (body, proto string) {
	t.Helper()
	resp, err := c.Get(url) //nolint:noctx // short-lived test client
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return string(b), resp.Proto
}

// h1Client is an HTTP/1.1 client (no HTTP/2) so the HTTP/1.1 branch of the multiplexer is exercised deterministically.
func h1Client(useTLS bool) *http.Client {
	tr := &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	if useTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // in-test self-signed cert
	}
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}

// h2Client forces HTTP/2: over TLS via ALPN, and over cleartext (h2c) via a plain dialer, so the multiplexer's content-type split is
// exercised with REST traffic that rides the same HTTP/2 the gRPC channel uses.
func h2Client(t *testing.T, useTLS bool, addr string) *http.Client {
	t.Helper()
	if useTLS {
		return &http.Client{
			Transport: &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // in-test self-signed cert
			Timeout:   3 * time.Second,
		}
	}
	return &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, a string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, a)
			},
		},
		Timeout: 3 * time.Second,
	}
}
