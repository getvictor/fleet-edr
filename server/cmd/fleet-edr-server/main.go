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

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *apiKey == "" {
		logger.Warn("no API key configured, all requests will be accepted")
	}

	logger.Info("fleet-edr-server starting", "addr", *addr)

	s, err := store.New(*dsn)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}
	defer s.Close()

	h := ingest.New(s, *apiKey, logger)
	q := graph.NewQuery(s)
	a := api.New(q, *apiKey, logger)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	a.RegisterRoutes(mux)

	// Serve the embedded React UI at /ui/.
	uiDist, err := fs.Sub(ui.DistFS, "dist")
	if err != nil {
		logger.Error("embed ui", "err", err)
		os.Exit(1)
	}
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(uiDist))))
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
		logger.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("shutdown error", "err", err)
		}
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
