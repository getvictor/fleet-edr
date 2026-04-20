// fleet-edr-ingest is a standalone event ingestion service. It accepts events
// from agents and writes them to MySQL without any processing. A separate
// fleet-edr-server instance polls for unprocessed events and builds process graphs.
//
// Same env surface as fleet-edr-server; processor knobs are ignored.
package main

import (
	"net/http"
	"os"
	"time"

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/bootstrap"
	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/ingest"
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
	env, err := bootstrap.Init(bootstrap.Options{ServiceName: serviceName, ServiceVersion: version})
	if err != nil {
		return err
	}
	defer env.FlushOTel()
	defer env.Cancel()
	ctx, cfg, logger := env.Ctx, env.Config, env.Logger

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

	h := ingest.New(s, logger, ingest.BuildInfo{Version: version, Commit: commit, BuildTime: buildTime})
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
	if cfg.TLSEnabled() {
		if err := httpserver.ConfigureTLS(ctx, srv, httpserver.TLSOptions{
			CertFile:   cfg.TLSCertFile,
			KeyFile:    cfg.TLSKeyFile,
			AllowTLS12: cfg.AllowTLS12,
			Logger:     logger,
		}); err != nil {
			return err
		}
	}
	return httpserver.RunAndShutdown(ctx, srv, cfg.TLSEnabled(), logger)
}
