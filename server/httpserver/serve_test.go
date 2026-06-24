package httpserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
)

func selfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// freeAddr returns a 127.0.0.1 address that was free a moment ago. There is a tiny TOCTOU window between closing the probe
// listener and RunAndShutdown re-listening; it is acceptable for a local test.
func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// TestRunAndShutdown_DrainThenGracefulShutdown drives RunAndShutdown through a SIGTERM-style ctx cancel: the drain flag flips so
// /readyz reports 503, an in-flight request that spans the drain window still completes successfully, and the call returns within
// the drain + shutdown deadline.
//
// spec:server-availability/sigterm-produces-a-load-balancer-drainable-graceful-shutdown/in-flight-requests-complete-before-the-listener-closes
// spec:server-availability/sigterm-produces-a-load-balancer-drainable-graceful-shutdown/the-process-exits-within-the-drain-plus-shutdown-deadline
func TestRunAndShutdown_DrainThenGracefulShutdown(t *testing.T) {
	t.Parallel()
	cert := selfSignedTLS(t)
	addr := freeAddr(t)
	drain := &httpserver.DrainState{}

	var slowStarted, slowDone atomic.Bool
	var slowStatus atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if drain.IsDraining() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		slowStarted.Store(true)
		// An in-flight request that spans the drain window and into graceful shutdown. Shutdown waits for it rather than
		// cancelling it, so the timer wins and the request returns 200.
		select {
		case <-time.After(250 * time.Millisecond):
		case <-r.Context().Done():
		}
		slowDone.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	const drainDelay = 100 * time.Millisecond
	go func() { done <- httpserver.RunAndShutdown(ctx, srv, slog.Default(), drain, drainDelay) }()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test client against a self-signed test cert
	}}
	base := "https://" + addr
	get := func(path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+path, nil)
		if err != nil {
			return nil, err
		}
		return client.Do(req)
	}

	// Wait for the server to accept TLS and report ready.
	require.Eventually(t, func() bool {
		resp, err := get("/readyz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond, "server did not come up ready")

	// Start a slow in-flight request, then cancel (SIGTERM).
	inflight := make(chan struct{})
	go func() {
		defer close(inflight)
		resp, err := get("/slow")
		if err != nil {
			return
		}
		slowStatus.Store(int64(resp.StatusCode))
		_ = resp.Body.Close()
	}()
	require.Eventually(t, slowStarted.Load, 2*time.Second, 10*time.Millisecond)

	shutdownStart := time.Now()
	cancel()

	// During the drain window readiness flips to 503 (the drain flag stays set for the rest of the lifetime).
	require.Eventually(t, func() bool {
		resp, err := get("/readyz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusServiceUnavailable
	}, 2*time.Second, 10*time.Millisecond, "readiness did not flip to 503 on drain")

	// RunAndShutdown returns within drain + ShutdownTimeout.
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(drainDelay + httpserver.ShutdownTimeout + 2*time.Second):
		t.Fatal("RunAndShutdown did not return within the drain + shutdown deadline")
	}
	assert.Less(t, time.Since(shutdownStart), drainDelay+httpserver.ShutdownTimeout,
		"process must exit within the drain + shutdown deadline")

	<-inflight
	assert.True(t, slowDone.Load(), "in-flight request must complete before shutdown returns")
	assert.Equal(t, int64(http.StatusOK), slowStatus.Load(), "in-flight request must complete successfully")
}
