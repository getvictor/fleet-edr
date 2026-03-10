// fleet-edr-ingest is a standalone event ingestion service. It accepts events
// from agents and writes them to MySQL without any processing. A separate
// fleet-edr-server instance polls for unprocessed events and builds process
// graphs.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/store"
)

func main() {
	var (
		addr   = flag.String("addr", ":8081", "Listen address")
		dsn    = flag.String("dsn", "root@tcp(127.0.0.1:3306)/edr", "MySQL DSN (user:pass@tcp(host:port)/db)")
		apiKey = flag.String("api-key", "", "Required API key for ingestion (empty = no auth)")
	)
	flag.Parse()

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *apiKey == "" {
		logger.WarnContext(ctx, "no API key configured, all requests will be accepted")
	}

	logger.InfoContext(ctx, "fleet-edr-ingest starting", "addr", *addr)

	s, err := store.New(ctx, *dsn)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		os.Exit(1)
	}
	defer func() { _ = s.Close() }()

	h := ingest.New(s, *apiKey, logger)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.InfoContext(ctx, "shutting down")
		shutdownCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.ErrorContext(ctx, "shutdown error", "err", err)
		}
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.ErrorContext(ctx, "server error", "err", err)
		os.Exit(1)
	}
}
