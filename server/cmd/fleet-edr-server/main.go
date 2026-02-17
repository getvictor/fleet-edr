// fleet-edr-server is a standalone Go service that receives EDR events
// from agents and stores them in PostgreSQL.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/store"
)

func main() {
	var (
		addr   = flag.String("addr", ":8080", "Listen address")
		dsn    = flag.String("dsn", "postgres://localhost/edr?sslmode=disable", "PostgreSQL connection string")
		apiKey = flag.String("api-key", "", "Required API key for ingestion (empty = no auth)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("fleet-edr-server starting on %s", *addr)

	s, err := store.New(*dsn)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer s.Close()

	h := ingest.New(s, *apiKey)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	srv := &http.Server{Addr: *addr, Handler: mux}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down")
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}
