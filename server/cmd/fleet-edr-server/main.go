// fleet-edr-server is the main EDR server that handles event processing,
// serves the API and UI. Event ingestion can be handled by this server or
// by a separate fleet-edr-ingest instance.
package main

import (
	"context"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fleetdm/edr/server/api"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/processor"
	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/ui"
)

func main() {
	var (
		addr             = flag.String("addr", ":8080", "Listen address")
		dsn              = flag.String("dsn", "root@tcp(127.0.0.1:3306)/edr", "MySQL DSN (user:pass@tcp(host:port)/db)")
		apiKey           = flag.String("api-key", "", "Required API key for ingestion (empty = no auth)")
		processInterval  = flag.Duration("process-interval", 500*time.Millisecond, "Interval between processing cycles")
		processBatchSize = flag.Int("process-batch", 500, "Max events per processing cycle")
	)
	flag.Parse()

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *apiKey == "" {
		logger.WarnContext(ctx, "no API key configured, all requests will be accepted")
	}

	logger.InfoContext(ctx, "fleet-edr-server starting", "addr", *addr)

	s, err := store.New(ctx, *dsn)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		os.Exit(1)
	}
	defer func() { _ = s.Close() }()

	// Ingest handler (also serves events when running as a single binary).
	h := ingest.New(s, *apiKey, logger)

	// Graph builder and processor — polls for unprocessed events.
	builder := graph.NewBuilder(s, logger)
	proc := processor.New(s, builder, logger, *processInterval, *processBatchSize)

	q := graph.NewQuery(s)
	a := api.New(q, s, *apiKey, logger)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	a.RegisterRoutes(mux)

	// Serve the embedded React UI at /ui/.
	uiDist, err := fs.Sub(ui.DistFS, "dist")
	if err != nil {
		logger.ErrorContext(ctx, "embed ui", "err", err)
		os.Exit(1)
	}
	// Serve static assets; fall back to index.html for React BrowserRouter.
	fileServer := http.FileServer(http.FS(uiDist))
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		// Strip prefix and try serving the file.
		path := r.URL.Path[len("/ui/"):]
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(uiDist, path); err != nil {
			// File not found — serve index.html for client-side routing.
			r.URL.Path = "/ui/"
		}
		http.StripPrefix("/ui/", fileServer).ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start the background event processor.
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	go func() {
		if err := proc.Run(procCtx); err != nil {
			logger.ErrorContext(ctx, "processor", "err", err)
		}
	}()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.InfoContext(ctx, "shutting down")
		procCancel()
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
