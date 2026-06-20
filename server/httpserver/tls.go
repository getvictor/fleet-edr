package httpserver

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// TLSOptions configures TLS for a fleet-edr daemon. CertFile and KeyFile must both be non-empty. The TLS floor is TLS 1.3,
// unconditionally: the only client is our own modern Go agent, so there is no legacy-client opt-out to maintain.
type TLSOptions struct {
	CertFile string
	KeyFile  string
	// Logger is required; the cert-reload loop logs through it. Using slog.Default() is acceptable.
	Logger *slog.Logger
}

// ConfigureTLS loads the cert + key, installs a TLS config on srv, and starts a
// SIGHUP watcher that atomically reloads the cert from disk. Existing connections
// keep their negotiated cert; only new handshakes see the replacement. The watcher
// goroutine exits cleanly when ctx is cancelled and releases the SIGHUP handler
// via signal.Stop so tests / embedded callers don't leak a goroutine past shutdown.
//
// Returns an error on initial cert-load failure; the SIGHUP watcher swallows
// subsequent reload failures (so a bad cert on disk doesn't crash the daemon
// mid-operation) and keeps the previous cert live.
func ConfigureTLS(ctx context.Context, srv *http.Server, opts TLSOptions) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		logger.ErrorContext(ctx, "load tls cert", "err", err)
		return err
	}
	certHolder := &atomic.Pointer[tls.Certificate]{}
	certHolder.Store(&cert)

	// TLS 1.3 floor, unconditionally. TLS 1.3 negotiates its own fixed cipher list, so no CipherSuites override is needed.
	srv.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certHolder.Load(), nil
		},
	}
	go watchSIGHUPForCertReload(ctx, opts.CertFile, opts.KeyFile, certHolder, logger)
	return nil
}

// watchSIGHUPForCertReload reloads the cert + key from disk on every SIGHUP and
// swaps it into certHolder atomically.
func watchSIGHUPForCertReload(ctx context.Context, certFile, keyFile string, certHolder *atomic.Pointer[tls.Certificate], logger *slog.Logger) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
			logger.InfoContext(ctx, "tls reload: reloading cert + key from disk")
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				logger.ErrorContext(ctx, "tls reload failed", "err", err)
				continue
			}
			certHolder.Store(&cert)
			logger.InfoContext(ctx, "tls reload", "cert_file", certFile)
		}
	}
}
