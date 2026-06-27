// fleet-edr-ingest is a standalone event ingestion service. It accepts events
// from agents and writes them to MySQL without any processing. A separate
// fleet-edr-server instance polls for unprocessed events and builds process graphs.
//
// Same env surface as fleet-edr-server; processor knobs are ignored.
package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/fleetdm/edr/internal/keyring"
	"github.com/fleetdm/edr/internal/observability/tracing"
	"github.com/fleetdm/edr/server/bootstrap"
	"github.com/fleetdm/edr/server/config"
	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	"github.com/fleetdm/edr/server/httpserver"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	observabilitybootstrap "github.com/fleetdm/edr/server/observability/bootstrap"
	"github.com/fleetdm/edr/server/tracingpolicy"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = ""
)

const (
	serviceName = "fleet-edr-ingest"

	// HTTP server timeouts. Read 10s covers the agent's worst-case slow upload of a full batch; write 30s and idle 60s keep
	// long-poll-style commands from getting cut off, but bound how long a stuck client can hold a connection. Same defaults as
	// fleet-edr-server.
	httpWriteTimeout = 30 * time.Second
	httpIdleTimeout  = 60 * time.Second
)

func main() {
	if err := run(); err != nil {
		_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(2)
	}
}

func run() error {
	// Build the route-tier trace sampler before bootstrap.Init so it is installed on the TracerProvider at OTel init. The ingest binary
	// serves the highest-volume route (POST /api/events), so capping its trace export is the main win of issue #374. Wrapped in
	// ParentBased so a sampled parent forces its children sampled.
	samplerRegistry := tracing.NewRegistry()
	tracingpolicy.Register(samplerRegistry)
	traceSampler := tracing.NewRouteTierSampler(samplerRegistry)

	ctx, env, err := bootstrap.Init(bootstrap.Options{
		ServiceName:    serviceName,
		ServiceVersion: version,
		TraceSampler:   sdktrace.ParentBased(traceSampler),
	})
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
	)

	db, err := bootstrap.OpenDB(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open db", "err", err)
		return err
	}
	defer func() { _ = db.Close() }()

	// ClickHouse is the event store (ADR-0015). The ingest tier fans every accepted event out to the ClickHouse archive plus the MySQL
	// EventLog queue, so EDR_CLICKHOUSE_DSN is required here too: an unset value is a fatal misconfig, not a MySQL fallback.
	if cfg.ClickHouseDSN == "" {
		logger.ErrorContext(ctx, "EDR_CLICKHOUSE_DSN is required: the event store is ClickHouse (ADR-0015)")
		return errors.New("EDR_CLICKHOUSE_DSN is required")
	}
	chDB, err := visibilitybootstrap.OpenClickHouse(ctx, cfg.ClickHouseDSN)
	if err != nil {
		logger.ErrorContext(ctx, "open clickhouse", "err", err)
		return err
	}
	defer func() { _ = chDB.Close() }()
	visibilityCtx, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db, ClickHouseDB: chDB, Logger: logger})
	if err != nil {
		logger.ErrorContext(ctx, "open visibility", "err", err)
		return err
	}
	if err := visibilityCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "visibility schema", "err", err)
		return err
	}

	// One root secret seeds every long-lived server-side key, same as fleet-edr-server. Deriving here (rather than skipping the keyring)
	// is mandatory: identity + endpoint bootstrap require the derived keys, and the labels MUST match fleet-edr-server's so a host token
	// or session cookie minted by one binary validates under the other.
	kr, err := keyring.New(cfg.SecretKey)
	if err != nil {
		logger.ErrorContext(ctx, "build keyring", "err", err)
		return fmt.Errorf("build keyring: %w", err)
	}
	// keyring.New holds its own copy of the root and cfg.SecretKey is not read past this point, so zero the config's copy to minimize how
	// long the raw root secret lives in memory (heap dumps, core files).
	clear(cfg.SecretKey)

	identityCtx, err := identitybootstrap.New(ctx, identitybootstrap.Deps{
		DB:                db,
		Logger:            logger,
		SessionSigningKey: kr.Derive(keyring.SessionSigningKeyLabel),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open identity", "err", err)
		return err
	}
	if err := identityCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "identity schema", "err", err)
		return err
	}

	// The observability context owns the runtime trace-sampler settings (issue #374). The ingest tier serves the highest-volume route
	// (POST /api/events), so it polls the same row to honor an operator's ratio / force-full change without a restart. It does NOT mount
	// the admin endpoint (ingest serves no operator routes), but it still needs the schema + read accessor.
	observabilityCtx, err := observabilitybootstrap.New(observabilitybootstrap.Deps{
		DB:     db,
		Logger: logger,
		AuthZ:  identityCtx.AuthZ(),
		Audit:  identityCtx.AuditRecorder(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open observability", "err", err)
		return err
	}
	if err := observabilityCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "observability schema", "err", err)
		return err
	}
	// Prime the sampler synchronously before serving so the ingest tier's first request honors any persisted override rather than the
	// compile-time defaults; then poll for later changes. The applied state is a per-replica cache, safe to lose (ADR-0010).
	samplerReader := observabilityCtx.TraceSamplerSettingsReader()
	primedSampler := tracing.PrimeSampler(ctx, traceSampler, samplerReader, logger)
	go tracing.StartSettingsPoller(ctx, traceSampler, samplerReader, logger, primedSampler)

	detectionCtx, err := detectionbootstrap.New(detectionbootstrap.Deps{
		DB:     db,
		Logger: logger,
		Mode:   detectionbootstrap.ModeIntake,
		Build: detectionbootstrap.BuildInfo{
			Version:   version,
			Commit:    commit,
			BuildTime: buildTime,
		},
		EventLog:     visibilityCtx.EventLog(),
		EventArchive: visibilityCtx.EventArchive(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open detection", "err", err)
		return err
	}
	if err := detectionCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "detection schema", "err", err)
		return err
	}

	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        cfg.EnrollSecret,
		EnrollRatePerMinute: cfg.EnrollRatePerMin,
		Audit:               identityCtx.AuditRecorder(),
		AuthZ:               identityCtx.AuthZ(),
		HostTokenLifetime:   config.DefaultHostTokenLifetime,
		HostTokenSigningKey: kr.Derive(keyring.HostTokenSigningLabel),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open endpoint", "err", err)
		return err
	}
	if err := endpointCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "endpoint schema", "err", err)
		return err
	}

	// Fail closed on the revocation snapshot: it is the only revocation enforcement on the no-DB verify hot path, so an empty snapshot
	// would accept already-revoked/epoch-bumped tokens. A failed initial load (right after the schema apply succeeded) is a real
	// outage, so refuse to serve rather than start allow-all. The background ticker keeps it fresh afterward.
	revSnap := endpointCtx.RevocationSnapshot()
	if rerr := revSnap.Refresh(ctx); rerr != nil {
		return fmt.Errorf("initial revocation snapshot load: %w", rerr)
	}
	go revSnap.Run(ctx, endpointbootstrap.DefaultRevocationRefreshInterval)

	hostTokenMW := endpointCtx.HostTokenMiddleware()

	mux := http.NewServeMux()
	detectionCtx.RegisterHealthRoutes(mux)
	endpointCtx.RegisterPublicRoutes(mux)
	mux.Handle("POST /api/events", hostTokenMW(detectionCtx.Service().IngestHandler()))
	mux.Handle("POST /api/token/refresh", hostTokenMW(endpointCtx.TokenRefreshHandler()))

	handler := httpserver.Build(mux, httpserver.Options{
		Logger:      logger,
		ServiceName: serviceName,
		TLSEnabled:  cfg.TLSEnabled(),
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: httpWriteTimeout,
		IdleTimeout:  httpIdleTimeout,
	}
	// Honor EDR_TLS_TERMINATED_BY_PROXY here too: config validation allows missing cert files in that mode, so calling
	// ConfigureTLS with empty paths would fail to load a keypair and brick ingest boot behind a proxy. Leaving TLSConfig nil
	// makes RunAndShutdown serve plaintext, matching the main server.
	if cfg.TLSTerminatedByProxy {
		logger.WarnContext(ctx, "ingest serving plaintext HTTP: EDR_TLS_TERMINATED_BY_PROXY=1 is set; only safe behind a "+
			"TLS-terminating proxy", "listen_addr", cfg.ListenAddr)
	} else if err := httpserver.ConfigureTLS(ctx, srv, httpserver.TLSOptions{
		CertFile: cfg.TLSCertFile,
		KeyFile:  cfg.TLSKeyFile,
		Logger:   logger,
	}); err != nil {
		return err
	}
	// The ingest binary shuts down immediately on SIGTERM (nil drain, 0 delay). Graceful-drain wiring for the ingest tier is a
	// follow-up to the server's (server-availability arc); nil/0 preserves the prior immediate-shutdown behavior with no regression.
	return httpserver.RunAndShutdown(ctx, srv, logger, nil, 0)
}
