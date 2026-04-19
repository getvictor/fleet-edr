// fleet-edr-ingest is a standalone event ingestion service. It accepts events
// from agents and writes them to MySQL without any processing. A separate
// fleet-edr-server instance polls for unprocessed events and builds process graphs.
//
// Same env surface as fleet-edr-server; processor knobs are ignored.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/logging"
	"github.com/fleetdm/edr/server/observability"
	"github.com/fleetdm/edr/server/store"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = ""
)

const serviceName = "fleet-edr-ingest"

func main() {
	if err := run(); err != nil {
		_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(2)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	shutdownOTel, err := observability.Init(ctx, observability.Options{
		ServiceName:    serviceName,
		ServiceVersion: version,
	})
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		if err := shutdownOTel(flushCtx); err != nil {
			slog.Default().WarnContext(flushCtx, "otel shutdown", "err", err)
		}
	}()

	logger, err := logging.New(os.Stderr, logging.Options{
		Level:               cfg.LogLevel,
		Format:              cfg.LogFormat,
		InstrumentationName: serviceName,
	})
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	logger.InfoContext(ctx, "fleet-edr-ingest starting",
		"addr", cfg.ListenAddr,
		"version", version,
		"commit", commit,
		"tls", cfg.TLSEnabled(),
	)
	if !cfg.TLSEnabled() {
		logger.WarnContext(ctx, "EDR_ALLOW_INSECURE_HTTP=1 set; TLS disabled — do not run in production")
	}

	s, err := store.New(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		return err
	}
	defer func() { _ = s.Close() }()

	enrollStore := enrollment.NewStore(s.DB())
	enrollHandler := enrollment.NewHandler(enrollStore, enrollment.Options{
		EnrollSecret:  cfg.EnrollSecret,
		RatePerMinute: cfg.EnrollRatePerMin,
		Logger:        logger,
	})

	h := ingest.New(s, logger, ingest.BuildInfo{
		Version: version, Commit: commit, BuildTime: buildTime,
	})

	hostTokenMW := authn.HostToken(enrollStore, logger)

	mux := http.NewServeMux()
	h.RegisterHealthRoutes(mux)
	enrollHandler.RegisterRoutes(mux)
	mux.Handle("POST /api/v1/events", hostTokenMW(h.IngestHandler()))

	handler := httpserver.Build(mux, httpserver.Options{
		Logger:      logger,
		ServiceName: serviceName,
		TLSEnabled:  cfg.TLSEnabled(),
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	var certHolder atomic.Pointer[tls.Certificate]
	if cfg.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			logger.ErrorContext(ctx, "load tls cert", "err", err)
			return err
		}
		certHolder.Store(&cert)
		minVer := uint16(tls.VersionTLS13)
		if cfg.AllowTLS12 {
			minVer = tls.VersionTLS12
		}
		//nolint:gosec // MinVersion may be TLS12 only when the operator explicitly opts in via EDR_TLS_ALLOW_TLS12=1.
		srv.TLSConfig = &tls.Config{
			MinVersion: minVer,
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
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for range sighup {
				cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
				if err != nil {
					logger.ErrorContext(ctx, "tls reload failed", "err", err)
					continue
				}
				certHolder.Store(&cert)
				logger.InfoContext(ctx, "tls reload")
			}
		}()
	}

	serverErr := make(chan error, 1)
	go func() {
		var serveErr error
		if cfg.TLSEnabled() {
			serveErr = srv.ListenAndServeTLS("", "")
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr <- serveErr
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		logger.InfoContext(context.Background(), "shutdown starting", "reason", ctx.Err())
	case err := <-serverErr:
		if err != nil {
			logger.ErrorContext(ctx, "server error", "err", err)
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "shutdown error", "err", err)
	}
	logger.InfoContext(shutdownCtx, "shutdown complete")
	return nil
}
