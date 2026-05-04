// fleet-edr-server is the main EDR server that handles event processing,
// serves the API and UI. Event ingestion can be handled by this server or
// by a separate fleet-edr-ingest instance.
package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/apidocs"
	"github.com/fleetdm/edr/server/bootstrap"
	"github.com/fleetdm/edr/server/config"
	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/metrics"
	responsebootstrap "github.com/fleetdm/edr/server/response/bootstrap"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/ui"
)

// serverGaugeSource adapts our endpoint Service + detection Service
// to the metrics.GaugeSource interface.
type serverGaugeSource struct {
	endpointSvc  endpointapi.Service
	detectionSvc detectionapi.Service
}

func (g serverGaugeSource) EnrolledHosts(ctx context.Context) (int, error) {
	return g.endpointSvc.CountActive(ctx)
}

func (g serverGaugeSource) OfflineHosts(ctx context.Context, threshold time.Duration) (int, error) {
	return g.detectionSvc.CountOfflineHosts(ctx, threshold)
}

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = ""
)

const serviceName = "fleet-edr-server"

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

	logger.InfoContext(ctx, "fleet-edr-server starting",
		"addr", cfg.ListenAddr,
		"version", version,
		"commit", commit,
		"build_time", buildTime,
		"tls", cfg.TLSEnabled(),
		"tls12_allowed", cfg.AllowTLS12,
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

	identityCtx, err := openIdentity(ctx, logger, db, cfg)
	if err != nil {
		return err
	}

	detectionCtx, err := openDetection(ctx, logger, db, cfg, identityCtx)
	if err != nil {
		return err
	}

	responseCtx, err := openResponse(ctx, logger, db, detectionCtx, identityCtx)
	if err != nil {
		return err
	}

	var endpointCtx *endpointbootstrap.Endpoint
	activeHostsLister := func(ctx context.Context) ([]string, error) {
		if endpointCtx == nil {
			return nil, errors.New("rules fanout: endpoint context not yet initialised")
		}
		return endpointCtx.Service().ActiveHostIDs(ctx)
	}
	rulesCtx, err := openRules(ctx, logger, db, cfg, activeHostsLister, responseCtx.Service().Insert, identityCtx)
	if err != nil {
		return err
	}
	detectionCtx.LoadActive(rulesCtx.ContentService())

	endpointCtx, err = openEndpoint(ctx, logger, db, cfg, rulesCtx.PolicyService(), responseCtx.Service().Insert, identityCtx)
	if err != nil {
		return err
	}

	// Build the metrics recorder AFTER detectionCtx + endpointCtx exist
	// so the gauge source can read live state from both. Wire it back
	// into detectionCtx via SetMetrics so the engine + intake +
	// pipeline (processttl + retention) all instrument: the
	// recorder + recorder consumer dependency cycle resolves through
	// this two-phase setup.
	metricsRec := metrics.New(
		serverGaugeSource{endpointSvc: endpointCtx.Service(), detectionSvc: detectionCtx.Service()},
		metrics.Options{OfflineThreshold: 5 * time.Minute},
	)
	detectionCtx.SetMetrics(metricsRec)

	seedAdmin(ctx, logger, identityCtx)

	mux := buildMux(muxDeps{
		detectionCtx: detectionCtx,
		endpointCtx:  endpointCtx,
		identityCtx:  identityCtx,
		rulesCtx:     rulesCtx,
		responseCtx:  responseCtx,
		logger:       logger,
	})
	registerUIRoutes(mux, logger)

	go runDetection(ctx, detectionCtx, logger)
	go runIdentity(ctx, identityCtx, logger)
	go watchSIGHUPForAuthzShadowMode(ctx, identityCtx, logger)

	// Only construct the resolver when EDR_TRUSTED_PROXIES is non-empty.
	// httpserver.Build skips installing the middleware on a nil resolver,
	// and httpserver.ClientIP's fallback returns the same peer IP the
	// resolver's empty-list path would return — so this saves one
	// per-request middleware hop in the default deployment (per Copilot
	// review on PR #113).
	var clientIPResolver *httpserver.ClientIPResolver
	if len(cfg.TrustedProxies) > 0 {
		clientIPResolver, err = httpserver.NewClientIPResolver(cfg.TrustedProxies)
		if err != nil {
			logger.ErrorContext(ctx, "EDR_TRUSTED_PROXIES invalid", "err", err)
			return err
		}
		logger.InfoContext(ctx, "trusting X-Forwarded-For from proxies", "trusted", cfg.TrustedProxies)
	}

	srv := newHTTPServer(cfg, mux, logger, clientIPResolver)
	if err := configureTLSIfEnabled(ctx, logger, srv, cfg); err != nil {
		return err
	}
	return httpserver.RunAndShutdown(ctx, srv, cfg.TLSEnabled(), logger)
}

func openIdentity(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
) (*identitybootstrap.Identity, error) {
	identityCtx, err := identitybootstrap.New(ctx, identitybootstrap.Deps{
		DB:              db,
		Logger:          logger,
		LoginRatePerMin: cfg.LoginRatePerMin,
		CookieSecure:    cfg.TLSEnabled(),
		AuthzShadowMode: cfg.AuthzShadowMode,
	})
	if err != nil {
		logger.ErrorContext(ctx, "open identity", "err", err)
		return nil, err
	}
	if err := identityCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "identity schema", "err", err)
		return nil, err
	}
	return identityCtx, nil
}

func openDetection(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
	identityCtx *identitybootstrap.Identity,
) (*detectionbootstrap.Detection, error) {
	detectionCtx, err := detectionbootstrap.New(detectionbootstrap.Deps{
		DB:     db,
		Logger: logger,
		Mode:   detectionbootstrap.ModeFull,
		Build: detectionbootstrap.BuildInfo{
			Version:   version,
			Commit:    commit,
			BuildTime: buildTime,
		},
		ProcessInterval:      cfg.ProcessInterval,
		ProcessBatch:         cfg.ProcessBatch,
		StaleProcessTTL:      cfg.StaleProcessTTL,
		StaleProcessInterval: cfg.StaleProcessInterval,
		RetentionDays:        cfg.RetentionDays,
		RetentionInterval:    cfg.RetentionInterval,
		UserExists:           identityCtx.Service().UserExists,
		Audit:                identityCtx.AuditRecorder(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open detection", "err", err)
		return nil, err
	}
	if err := detectionCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "detection schema", "err", err)
		return nil, err
	}
	if err := detectionCtx.MigrateSchema(ctx); err != nil {
		logger.ErrorContext(ctx, "detection migrate", "err", err)
		return nil, err
	}
	return detectionCtx, nil
}

func openResponse(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	detectionCtx *detectionbootstrap.Detection,
	identityCtx *identitybootstrap.Identity,
) (*responsebootstrap.Response, error) {
	responseCtx, err := responsebootstrap.New(responsebootstrap.Deps{
		DB:        db,
		Logger:    logger,
		Heartbeat: detectionCtx.Service().RecordHostSeen,
		Audit:     identityCtx.AuditRecorder(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open response", "err", err)
		return nil, err
	}
	if err := responseCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "response schema", "err", err)
		return nil, err
	}
	return responseCtx, nil
}

func openRules(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
	activeHostsLister rulesbootstrap.ActiveHostsLister,
	cmdInserter rulesbootstrap.CommandInserter,
	identityCtx *identitybootstrap.Identity,
) (*rulesbootstrap.Rules, error) {
	rulesCtx, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:     db,
		Logger: logger,
		RegistryOptions: rulesapi.RegistryOptions{
			SuspiciousExecParentAllowlist: cfg.SuspiciousExecParentAllowlist,
			LaunchAgentAllowlist:          cfg.LaunchAgentAllowlist,
			LaunchDaemonTeamIDAllowlist:   cfg.LaunchDaemonTeamIDAllowlist,
			SudoersWriterAllowlist:        cfg.SudoersWriterAllowlist,
		},
		ActiveHostsLister: activeHostsLister,
		CommandInserter:   cmdInserter,
		Audit:             identityCtx.AuditRecorder(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open rules", "err", err)
		return nil, err
	}
	if err := rulesCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "rules schema", "err", err)
		return nil, err
	}
	return rulesCtx, nil
}

func openEndpoint(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
	policySvc endpointapi.PolicyProvider,
	cmdInserter endpointbootstrap.CommandInserter,
	identityCtx *identitybootstrap.Identity,
) (*endpointbootstrap.Endpoint, error) {
	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        cfg.EnrollSecret,
		EnrollRatePerMinute: cfg.EnrollRatePerMin,
		PolicyProvider:      policySvc,
		CommandInserter:     cmdInserter,
		Audit:               identityCtx.AuditRecorder(),
		HostTokenLifetime:   cfg.HostTokenLifetime,
		HostTokenGrace:      cfg.HostTokenGrace,
	})
	if err != nil {
		logger.ErrorContext(ctx, "open endpoint", "err", err)
		return nil, err
	}
	if err := endpointCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "endpoint schema", "err", err)
		return nil, err
	}
	return endpointCtx, nil
}

func seedAdmin(ctx context.Context, logger *slog.Logger, identityCtx *identitybootstrap.Identity) {
	if _, _, err := identityCtx.Service().SeedAdmin(ctx, os.Stderr); err != nil &&
		!errors.Is(err, identityapi.ErrAlreadySeeded) {
		logger.ErrorContext(ctx, "admin seed failed", "err", err)
	}
}

func configureTLSIfEnabled(ctx context.Context, logger *slog.Logger, srv *http.Server, cfg *config.Config) error {
	if !cfg.TLSEnabled() {
		return nil
	}
	return httpserver.ConfigureTLS(ctx, srv, httpserver.TLSOptions{
		CertFile:   cfg.TLSCertFile,
		KeyFile:    cfg.TLSKeyFile,
		AllowTLS12: cfg.AllowTLS12,
		Logger:     logger,
	})
}

func runDetection(ctx context.Context, detectionCtx *detectionbootstrap.Detection, logger *slog.Logger) {
	if err := detectionCtx.Run(ctx); err != nil && ctx.Err() == nil {
		logger.ErrorContext(ctx, "detection run", "err", err)
	}
}

func runIdentity(ctx context.Context, identityCtx *identitybootstrap.Identity, logger *slog.Logger) {
	if err := identityCtx.Run(ctx); err != nil && ctx.Err() == nil {
		logger.ErrorContext(ctx, "identity run", "err", err)
	}
}

// watchSIGHUPForAuthzShadowMode re-reads EDR_AUTHZ_SHADOW_MODE on every
// SIGHUP and calls Identity.SetAuthzShadowMode. Multiple SIGHUP
// listeners coexist via signal.Notify; the TLS reloader in
// httpserver.ConfigureTLS uses the same signal for cert reload, so an
// operator's `kill -HUP <pid>` flips both.
//
// The SIGHUP-driven reload exists so a pilot deployment can swap from
// shadow to enforcement (or back, if the dashboard surfaces an
// unexpected deny) without a server restart. The wave-1 production
// rollout walks operators through this exact procedure.
func watchSIGHUPForAuthzShadowMode(ctx context.Context, identityCtx *identitybootstrap.Identity, logger *slog.Logger) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
			on := os.Getenv("EDR_AUTHZ_SHADOW_MODE") == "1"
			identityCtx.SetAuthzShadowMode(on)
			logger.InfoContext(ctx, "authz shadow mode reloaded",
				"edr.authz.shadow_mode", on)
		}
	}
}

func newHTTPServer(cfg *config.Config, mux *http.ServeMux, logger *slog.Logger, clientIPResolver *httpserver.ClientIPResolver) *http.Server {
	handler := httpserver.Build(mux, httpserver.Options{
		Logger:           logger,
		ServiceName:      serviceName,
		TLSEnabled:       cfg.TLSEnabled(),
		ClientIPResolver: clientIPResolver,
	})
	return &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

type muxDeps struct {
	detectionCtx *detectionbootstrap.Detection
	endpointCtx  *endpointbootstrap.Endpoint
	identityCtx  *identitybootstrap.Identity
	rulesCtx     *rulesbootstrap.Rules
	responseCtx  *responsebootstrap.Response
	logger       *slog.Logger
}

func buildMux(d muxDeps) *http.ServeMux {
	mux := http.NewServeMux()
	d.detectionCtx.RegisterHealthRoutes(mux)
	d.endpointCtx.RegisterPublicRoutes(mux)
	d.identityCtx.RegisterPublicRoutes(mux)
	apidocs.RegisterRoutes(mux)

	registerHostRoutes(mux, d)
	registerSessionRoutes(mux, d)
	return mux
}

func registerHostRoutes(mux *http.ServeMux, d muxDeps) {
	hostTokenMW := d.endpointCtx.HostTokenMiddleware()
	hostMux := http.NewServeMux()
	hostMux.Handle("POST /api/events", d.detectionCtx.Service().IngestHandler())
	d.responseCtx.RegisterAgentRoutes(hostMux)
	hostProtected := hostTokenMW(hostMux)
	for _, p := range []string{
		"POST /api/events",
		"GET /api/commands",
		"PUT /api/commands/{id}",
	} {
		mux.Handle(p, hostProtected)
	}
}

func registerSessionRoutes(mux *http.ServeMux, d muxDeps) {
	sessionMW := d.identityCtx.SessionMiddleware()
	csrfMW := d.identityCtx.CSRFMiddleware()
	apiMux := http.NewServeMux()
	d.detectionCtx.RegisterAuthedRoutes(apiMux)
	d.rulesCtx.RegisterAuthedRoutes(apiMux)
	d.endpointCtx.RegisterAuthedRoutes(apiMux)
	d.responseCtx.RegisterAuthedRoutes(apiMux)
	d.identityCtx.RegisterAuthedRoutes(apiMux)
	sessionProtected := sessionMW(csrfMW(apiMux))
	for _, p := range []string{
		"GET /api/hosts", "GET /api/hosts/{host_id}/tree", "GET /api/hosts/{host_id}/processes/{pid}",
		"GET /api/alerts", "GET /api/alerts/{id}", "PUT /api/alerts/{id}",
		"GET /api/commands/{id}", "POST /api/commands",
		"GET /api/enrollments", "POST /api/enrollments/{host_id}/revoke", "POST /api/enrollments/{host_id}/rotate",
		"GET /api/policy", "PUT /api/policy",
		"GET /api/attack-coverage",
		"GET /api/rules",
		"GET /api/audit",
		"GET /api/session",
	} {
		mux.Handle(p, sessionProtected)
	}
}

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
	fileServer := http.StripPrefix("/ui/", http.FileServer(http.FS(uiDist)))
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		// Serve the requested file when it exists; otherwise rewrite to
		// index.html so React Router takes over for client-side deep
		// links (e.g. /ui/hosts/{id}, /ui/alerts/{id}).
		//
		// We can't reuse fileServer for the SPA fallback because Go's
		// http.FileServer redirects requests for `index.html` to `./`
		// (it tries to canonicalise URLs that name an index file). That
		// turns /ui/hosts/{id} into a 301 → /ui/hosts/, which then hits
		// the same redirect chain again. Open the bytes directly here.
		stripped := r.URL.Path[len("/ui/"):]
		if stripped == "" {
			serveIndex(w, r, uiDist, logger)
			return
		}
		if _, err := fs.Stat(uiDist, stripped); err != nil {
			serveIndex(w, r, uiDist, logger)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
}

// serveIndex writes the embedded SPA index.html bytes directly. Used
// as the SPA fallback so React Router handles deep links like
// /ui/hosts/{id} client-side without bouncing through http.FileServer's
// canonicalisation redirect for index files.
func serveIndex(w http.ResponseWriter, r *http.Request, uiDist fs.FS, logger *slog.Logger) {
	f, err := uiDist.Open("index.html")
	if err != nil {
		logger.ErrorContext(r.Context(), "open ui index.html", "err", err)
		http.Error(w, "ui index missing", http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if _, err := io.Copy(w, f); err != nil {
		logger.WarnContext(r.Context(), "copy ui index.html", "err", err)
	}
}
