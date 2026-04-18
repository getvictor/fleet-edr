// fleet-edr-ingest is a standalone event ingestion service. It accepts events
// from agents and writes them to MySQL without any processing. A separate
// fleet-edr-server instance polls for unprocessed events and builds process graphs.
//
// Configuration is the same env-var set as fleet-edr-server (see server/config). This binary
// ignores the processor-related knobs.
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fleetdm/edr/server/config"
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
	// Defer shutdown as soon as Init succeeds so any later startup failure still flushes
	// buffered OTel telemetry on its way out.
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

	s, err := store.New(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		return err
	}
	defer func() { _ = s.Close() }()

	h := ingest.New(s, cfg.BearerToken, logger, ingest.BuildInfo{
		Version: version, Commit: commit, BuildTime: buildTime,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	handler := httpserver.Build(mux, httpserver.Options{
		Logger:      logger,
		ServiceName: serviceName,
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if cfg.TLSEnabled() {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	serverErr := make(chan error, 1)
	go func() {
		var serveErr error
		if cfg.TLSEnabled() {
			serveErr = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
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
	// OTel shutdown handled by the deferred flusher installed right after observability.Init.
	return nil
}
