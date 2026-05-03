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

	"github.com/fleetdm/edr/server/bootstrap"
	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	"github.com/fleetdm/edr/server/httpserver"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
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
	ctx, env, err := bootstrap.Init(bootstrap.Options{ServiceName: serviceName, ServiceVersion: version})
	if err != nil {
		return err
	}
	defer env.FlushOTel()
	defer env.Cancel()
	cfg, logger := env.Config, env.Logger

	logger.InfoContext(ctx, "fleet-edr-ingest starting",
		"addr", cfg.ListenAddr,
		"version", version,
		"commit", commit,
		"tls", cfg.TLSEnabled(),
	)
	if !cfg.TLSEnabled() {
		logger.WarnContext(ctx, "EDR_ALLOW_INSECURE_HTTP=1 set; TLS disabled — do not run in production")
	}

	db, err := bootstrap.OpenDB(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open db", "err", err)
		return err
	}
	defer func() { _ = db.Close() }()

	identityCtx, err := identitybootstrap.New(identitybootstrap.Deps{DB: db, Logger: logger})
	if err != nil {
		logger.ErrorContext(ctx, "open identity", "err", err)
		return err
	}
	if err := identityCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "identity schema", "err", err)
		return err
	}

	detectionCtx, err := detectionbootstrap.New(detectionbootstrap.Deps{
		DB:     db,
		Logger: logger,
		Mode:   detectionbootstrap.ModeIntake,
		Build: detectionbootstrap.BuildInfo{
			Version:   version,
			Commit:    commit,
			BuildTime: buildTime,
		},
	})
	if err != nil {
		logger.ErrorContext(ctx, "open detection", "err", err)
		return err
	}
	if err := detectionCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "detection schema", "err", err)
		return err
	}
	if err := detectionCtx.MigrateSchema(ctx); err != nil {
		logger.ErrorContext(ctx, "detection migrate", "err", err)
		return err
	}

	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        cfg.EnrollSecret,
		EnrollRatePerMinute: cfg.EnrollRatePerMin,
	})
	if err != nil {
		logger.ErrorContext(ctx, "open endpoint", "err", err)
		return err
	}
	if err := endpointCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "endpoint schema", "err", err)
		return err
	}

	hostTokenMW := endpointCtx.HostTokenMiddleware()

	mux := http.NewServeMux()
	detectionCtx.RegisterHealthRoutes(mux)
	endpointCtx.RegisterPublicRoutes(mux)
	mux.Handle("POST /api/events", hostTokenMW(detectionCtx.Service().IngestHandler()))

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
