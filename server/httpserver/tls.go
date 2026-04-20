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

// TLSOptions configures TLS for a fleet-edr daemon. CertFile and KeyFile must both
// be non-empty. AllowTLS12 drops the floor from TLS 1.3 to 1.2 only when the
// operator explicitly opts in (EDR_TLS_ALLOW_TLS12=1).
type TLSOptions struct {
	CertFile   string
	KeyFile    string
	AllowTLS12 bool
	// Logger is required; the TLS cipher-list warning and the cert-reload loop both
	// log through it. Using slog.Default() is acceptable.
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

	minVer := uint16(tls.VersionTLS13)
	if opts.AllowTLS12 {
		minVer = tls.VersionTLS12
		logger.WarnContext(ctx, "EDR_TLS_ALLOW_TLS12=1 set; TLS 1.2 enabled for legacy pilot")
	}
	//nolint:gosec // MinVersion may be TLS12 only when the operator explicitly opts in via EDR_TLS_ALLOW_TLS12=1.
	srv.TLSConfig = &tls.Config{
		MinVersion: minVer,
		// TLS 1.2 cipher list restricted to forward-secrecy AEADs. TLS 1.3 has its
		// own fixed list, so this only takes effect when AllowTLS12 is on.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
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
