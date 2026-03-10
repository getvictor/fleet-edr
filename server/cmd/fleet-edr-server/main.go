// fleet-edr-server is a standalone Go service that receives EDR events
// from agents and stores them in MySQL.
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
	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/ui"
)

func main() {
	var (
		addr   = flag.String("addr", ":8080", "Listen address")
		dsn    = flag.String("dsn", "root@tcp(127.0.0.1:3306)/edr", "MySQL DSN (user:pass@tcp(host:port)/db)")
		apiKey = flag.String("api-key", "", "Required API key for ingestion (empty = no auth)")
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

	h := ingest.New(s, *apiKey, logger)
	q := graph.NewQuery(s)
	a := api.New(q, *apiKey, logger)

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
