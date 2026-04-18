// fleet-edr-server is the main EDR server that handles event processing,
// serves the API and UI. Event ingestion can be handled by this server or
// by a separate fleet-edr-ingest instance.
//
// Configuration is loaded from environment variables; see server/config for the full list.
// Start it with EDR_DSN, EDR_BEARER_TOKEN, and optionally the OTEL_* vars that route traces
// and logs to a collector (SigNoz, Tempo, Datadog, ...).
package main

import (
	"context"
	"crypto/tls"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fleetdm/edr/server/api"
	"github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/detection/rules"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/logging"
	"github.com/fleetdm/edr/server/observability"
	"github.com/fleetdm/edr/server/processor"
	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/ui"
)

// Build info injected via -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = ""
)

const serviceName = "fleet-edr-server"

func main() {
	if err := run(); err != nil {
		// At this point the structured logger may not be initialised (e.g. config load failure);
		// write the final message to stderr directly so the operator sees it.
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

	logger, err := logging.New(os.Stderr, logging.Options{
		Level:               cfg.LogLevel,
		Format:              cfg.LogFormat,
		InstrumentationName: serviceName,
	})
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	logger.InfoContext(ctx, "fleet-edr-server starting",
		"addr", cfg.ListenAddr,
		"version", version,
		"commit", commit,
		"build_time", buildTime,
		"tls", cfg.TLSEnabled(),
	)

	s, err := store.New(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		return err
	}
	defer func() { _ = s.Close() }()

	build := ingest.BuildInfo{Version: version, Commit: commit, BuildTime: buildTime}
	ingestHandler := ingest.New(s, cfg.BearerToken, logger, build)
	builder := graph.NewBuilder(s, logger)
	det := detection.NewEngine(s, logger)
	det.Register(&rules.SuspiciousExec{})
	proc := processor.New(s, builder, det, logger, cfg.ProcessInterval, cfg.ProcessBatch)

	q := graph.NewQuery(s)
	apiHandler := api.New(q, s, cfg.BearerToken, logger)

	mux := http.NewServeMux()
	ingestHandler.RegisterRoutes(mux)
	apiHandler.RegisterRoutes(mux)
	registerUIRoutes(mux, logger)

	// Start the background event processor.
	go func() {
		if err := proc.Run(ctx); err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "processor", "err", err)
		}
	}()

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
		logger.InfoContext(context.Background(), "shutdown starting", "signal", ctx.Err())
	case err := <-serverErr:
		if err != nil {
			logger.ErrorContext(ctx, "server error", "err", err)
			cancel()
			flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer flushCancel()
			_ = shutdownOTel(flushCtx)
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "shutdown error", "err", err)
	}
	if err := shutdownOTel(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "otel shutdown error", "err", err)
	}
	logger.InfoContext(shutdownCtx, "shutdown complete")
	return nil
}

// registerUIRoutes serves the embedded React UI at /ui/ and redirects / to /ui/.
func registerUIRoutes(mux *http.ServeMux, logger *slog.Logger) {
	uiDist, err := fs.Sub(ui.DistFS, "dist")
	if err != nil {
		logger.ErrorContext(context.Background(), "embed ui", "err", err)
		mux.HandleFunc("/ui/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "UI bundle missing; run `npm run build` in ui/ and rebuild the server", http.StatusServiceUnavailable)
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/", http.StatusFound)
		})
		return
	}
	fileServer := http.FileServer(http.FS(uiDist))
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/ui/"):]
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(uiDist, path); err != nil {
			r.URL.Path = "/ui/"
		}
		http.StripPrefix("/ui/", fileServer).ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
}
