// fleet-edr-server is the main EDR server that handles event processing,
// serves the API and UI. Event ingestion can be handled by this server or
// by a separate fleet-edr-ingest instance.
//
// Configuration is loaded from environment variables; see server/config for the full list.
// Start it with EDR_DSN, EDR_ENROLL_SECRET, TLS cert files (or
// EDR_ALLOW_INSECURE_HTTP=1 for dev), and optionally the OTEL_* vars that route traces and
// logs to a collector (SigNoz, Tempo, Datadog, ...).
package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/api"
	"github.com/fleetdm/edr/server/apidocs"
	"github.com/fleetdm/edr/server/bootstrap"
	"github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/detection"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/metrics"
	"github.com/fleetdm/edr/server/processor"
	"github.com/fleetdm/edr/server/processttl"
	responsebootstrap "github.com/fleetdm/edr/server/response/bootstrap"
	"github.com/fleetdm/edr/server/retention"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/ui"
)

// serverGaugeSource adapts our endpoint Service + store handle to the
// metrics.GaugeSource interface. Lives here (not in the metrics package)
// so the metrics package stays free of MySQL + endpoint dependencies and
// testable without a real DB.
type serverGaugeSource struct {
	endpointSvc endpointapi.Service
	store       *store.Store
}

func (g serverGaugeSource) EnrolledHosts(ctx context.Context) (int, error) {
	return g.endpointSvc.CountActive(ctx)
}

func (g serverGaugeSource) OfflineHosts(ctx context.Context, threshold time.Duration) (int, error) {
	return g.store.CountOfflineHosts(ctx, threshold)
}

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

	// Open the shared connection pool first; identity + store both consume it.
	db, err := store.OpenDB(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open db", "err", err)
		return err
	}
	defer func() { _ = db.Close() }()

	// Identity context (operator users + sessions). ApplySchema MUST run
	// before store.New because store.applySchema includes the
	// fk_alerts_updated_by FK that references users(id). Phase 5 drops that
	// FK and the call ordering will no longer matter.
	identityCtx, err := identitybootstrap.New(identitybootstrap.Deps{
		DB:              db,
		Logger:          logger,
		LoginRatePerMin: cfg.LoginRatePerMin,
		CookieSecure:    cfg.TLSEnabled(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open identity", "err", err)
		return err
	}
	if err := identityCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "identity schema", "err", err)
		return err
	}

	s, err := store.New(ctx, db)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		return err
	}

	build := ingest.BuildInfo{Version: version, Commit: commit, BuildTime: buildTime}
	ingestHandler := ingest.New(s, logger, build)
	builder := graph.NewBuilder(s, logger)
	det := detection.NewEngine(s, logger)
	proc := processor.New(s, builder, det, logger, cfg.ProcessInterval, cfg.ProcessBatch)

	q := graph.NewQuery(s)
	apiHandler := api.New(q, s, logger)

	// Response context: agent command queue. Built first because both
	// rules and endpoint consume responseCtx.Service().Insert eagerly
	// (as method values) for their fan-out paths. The Heartbeat closure
	// wraps store.UpdateHostLastSeen so the /api/commands poll's
	// last-seen-ns side effect survives the move; phase 5 swaps the
	// closure to detectionCtx.RecordHostSeen.
	responseCtx, err := responsebootstrap.New(responsebootstrap.Deps{
		DB:     db,
		Logger: logger,
		Heartbeat: func(ctx context.Context, hostID string, at time.Time) error {
			return s.UpdateHostLastSeen(ctx, hostID, at)
		},
	})
	if err != nil {
		logger.ErrorContext(ctx, "open response", "err", err)
		return err
	}
	if err := responseCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "response schema", "err", err)
		return err
	}

	// Late-binding closure: rules's fan-out needs the endpoint
	// service to enumerate active hosts, but endpoint hasn't been
	// constructed yet (it needs rules's PolicyService). The closure
	// captures endpointCtx by name; cmd/main always assigns it
	// before serving requests, so a fan-out call before that point
	// is impossible.
	var endpointCtx *endpointbootstrap.Endpoint
	rulesCtx, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:     db,
		Logger: logger,
		RegistryOptions: rulesapi.RegistryOptions{
			SuspiciousExecParentAllowlist: cfg.SuspiciousExecParentAllowlist,
			LaunchAgentAllowlist:          cfg.LaunchAgentAllowlist,
			LaunchDaemonTeamIDAllowlist:   cfg.LaunchDaemonTeamIDAllowlist,
			SudoersWriterAllowlist:        cfg.SudoersWriterAllowlist,
		},
		ActiveHostsLister: func(ctx context.Context) ([]string, error) {
			// Defensive nil check: cmd/main always assigns endpointCtx
			// before serving requests, so this branch is unreachable in
			// production. A future refactor could break the ordering;
			// returning an error keeps the server up and surfaces a
			// recognisable signal in the operator's audit log instead
			// of crashing the process.
			if endpointCtx == nil {
				return nil, errors.New("rules fanout: endpoint context not yet initialised")
			}
			return endpointCtx.Service().ActiveHostIDs(ctx)
		},
		CommandInserter: responseCtx.Service().Insert,
	})
	if err != nil {
		logger.ErrorContext(ctx, "open rules", "err", err)
		return err
	}
	if err := rulesCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "rules schema", "err", err)
		return err
	}
	det.LoadActive(rulesCtx.ContentService())

	endpointCtx, err = openEndpoint(ctx, logger, db, cfg, rulesCtx.PolicyService(), responseCtx.Service().Insert)
	if err != nil {
		return err
	}

	// Phase 4: OTel metrics recorder. Instruments register against the global meter
	// provider wired by observability.Init; counters, histograms, and observable
	// gauges flow through the same OTLP pipeline as traces + logs, so SigNoz (or any
	// OTLP backend) sees them without a separate scrape endpoint. Gauge source
	// queries live state on each collection via the endpointCtx + s adapter.
	metricsRec := metrics.New(
		serverGaugeSource{endpointSvc: endpointCtx.Service(), store: s},
		metrics.Options{OfflineThreshold: 5 * time.Minute},
	)
	ingestHandler.SetMetrics(metricsRec)
	det.SetMetrics(metricsRec)

	// Seed the first admin before we bind the HTTP listener. ErrAlreadySeeded
	// is the success-but-noop case (table already populated). Any other error
	// is logged but non-fatal -- the operator can still run migrations by hand.
	if _, _, err := identityCtx.Service().SeedAdmin(ctx, os.Stderr); err != nil &&
		!errors.Is(err, identityapi.ErrAlreadySeeded) {
		logger.ErrorContext(ctx, "admin seed failed", "err", err)
	}

	mux := buildMux(muxDeps{
		ingestHandler: ingestHandler,
		endpointCtx:   endpointCtx,
		identityCtx:   identityCtx,
		rulesCtx:      rulesCtx,
		responseCtx:   responseCtx,
		apiHandler:    apiHandler,
		logger:        logger,
	})
	registerUIRoutes(mux, logger)

	// Phase 4: retention runner. Skipped entirely when RetentionDays == 0.
	retentionRunner := retention.New(s.DB(), retention.Options{
		RetentionDays: cfg.RetentionDays,
		Interval:      cfg.RetentionInterval,
		Logger:        logger,
		Metrics:       metricsRec,
	})
	go retentionRunner.Loop(ctx)
	// Phase 7 / issue #6: force-exit processes whose exit event never
	// arrived. Skipped entirely when StaleProcessTTL == 0.
	processTTLRunner := processttl.New(s, processttl.Options{
		MaxAge:   cfg.StaleProcessTTL,
		Interval: cfg.StaleProcessInterval,
		Logger:   logger,
		Metrics:  metricsRec,
	})
	go processTTLRunner.Loop(ctx)
	go func() {
		if err := identityCtx.Run(ctx); err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "identity run", "err", err)
		}
	}()
	go runProcessor(ctx, proc, logger)

	srv := newHTTPServer(cfg, mux, logger)
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

// openEndpoint wires the endpoint bounded context (host enrollment +
// host-token verification) and applies its schema. PolicyProvider is
// satisfied by rules/api.PolicyService (phase 3); cmdInserter is
// satisfied by response.Service.Insert as a method value (phase 4).
// Extracted from run() to keep that function under the
// cognitive-complexity gate.
func openEndpoint(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
	policySvc endpointapi.PolicyProvider,
	cmdInserter endpointbootstrap.CommandInserter,
) (*endpointbootstrap.Endpoint, error) {
	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        cfg.EnrollSecret,
		EnrollRatePerMinute: cfg.EnrollRatePerMin,
		PolicyProvider:      policySvc,
		CommandInserter:     cmdInserter,
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

// runProcessor owns the background event-processor goroutine and logs any
// non-shutdown-induced exit as an error so SigNoz alerts fire if the processor
// dies while the server is otherwise healthy.
func runProcessor(ctx context.Context, proc *processor.Processor, logger *slog.Logger) {
	if err := proc.Run(ctx); err != nil && ctx.Err() == nil {
		logger.ErrorContext(ctx, "processor", "err", err)
	}
}

// newHTTPServer builds the *http.Server wrapped in the full httpserver
// middleware chain. Timeouts are conservative MVP-scale defaults; pushing them
// lower would starve slow clients on a residential NAT.
func newHTTPServer(cfg *config.Config, mux *http.ServeMux, logger *slog.Logger) *http.Server {
	handler := httpserver.Build(mux, httpserver.Options{
		Logger:      logger,
		ServiceName: serviceName,
		TLSEnabled:  cfg.TLSEnabled(),
	})
	return &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// muxDeps bundles the handlers + bounded-context handles the HTTP mux assembly
// needs, so buildMux takes a single argument and new middleware layers don't
// keep widening the signature.
type muxDeps struct {
	ingestHandler *ingest.Handler
	endpointCtx   *endpointbootstrap.Endpoint
	identityCtx   *identitybootstrap.Identity
	rulesCtx      *rulesbootstrap.Rules
	responseCtx   *responsebootstrap.Response
	apiHandler    *api.Handler
	logger        *slog.Logger
}

// buildMux composes the HTTP surface out of three authorization domains:
//   - public:  /livez, /readyz, /health, POST /api/enroll, POST /api/session,
//     DELETE /api/session (logout is best-effort and idempotent;
//     tolerating an unknown session avoids forcing a session probe
//     before a logout request)
//   - host:    POST /api/events, GET /api/commands, PUT /api/commands/{id}
//     (wrapped in endpoint HostToken middleware -- the agent polls for + reports on its own commands)
//   - session: /api/hosts/**, /api/alerts/**, /api/enrollments/**, /api/policy,
//     /api/attack-coverage, /api/rules, POST /api/commands, GET /api/commands/{id},
//     GET /api/session (wrapped in identity Session; unsafe methods additionally
//     gated by identity CSRF)
//
// Middleware is applied per-handler at registration time so one mux serves the whole
// surface instead of chaining multiple servers.
func buildMux(d muxDeps) *http.ServeMux {
	mux := http.NewServeMux()
	d.ingestHandler.RegisterHealthRoutes(mux)
	d.endpointCtx.RegisterPublicRoutes(mux)
	// POST + DELETE /api/session are public -- login mints a session, logout
	// is permissive (a stale cookie still needs a clearing Set-Cookie). The
	// identity context owns rate-limiting + audit log on these.
	d.identityCtx.RegisterPublicRoutes(mux)
	// Self-hosted Redoc at /api/docs (the matching spec at /api/openapi.yaml).
	// Public on purpose: same content is on the GitHub release page and
	// procurement teams browse it pre-eval.
	apidocs.RegisterRoutes(mux)

	registerHostRoutes(mux, d)
	registerSessionRoutes(mux, d)
	return mux
}

// registerHostRoutes wires the host-token protected agent endpoints onto mux. A
// dedicated sub-mux keeps the agent routes (ingest + response agent surface)
// scoped together under a single HostToken middleware.
func registerHostRoutes(mux *http.ServeMux, d muxDeps) {
	hostTokenMW := d.endpointCtx.HostTokenMiddleware()
	hostMux := http.NewServeMux()
	hostMux.Handle("POST /api/events", d.ingestHandler.IngestHandler())
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

// registerSessionRoutes wires the session-gated admin + UI-facing API. GET /commands
// and PUT /commands/{id} are deliberately host-token-only — those paths are the
// agent-facing command protocol. Admin UI command management (POST, GET /{id}) goes
// here. Session first (reads cookie, pins user + session on ctx), CSRF second (reads
// session off ctx, validates X-CSRF-Token on unsafe methods). GET + DELETE
// /api/session live under the same stack; login POST is public.
func registerSessionRoutes(mux *http.ServeMux, d muxDeps) {
	sessionMW := d.identityCtx.SessionMiddleware()
	csrfMW := d.identityCtx.CSRFMiddleware()
	apiMux := http.NewServeMux()
	d.apiHandler.RegisterRoutes(apiMux)
	d.rulesCtx.RegisterAuthedRoutes(apiMux)
	d.endpointCtx.RegisterAuthedRoutes(apiMux)
	d.responseCtx.RegisterAuthedRoutes(apiMux)
	d.identityCtx.RegisterAuthedRoutes(apiMux)
	sessionProtected := sessionMW(csrfMW(apiMux))
	for _, p := range []string{
		"GET /api/hosts", "GET /api/hosts/{host_id}/tree", "GET /api/hosts/{host_id}/processes/{pid}",
		"GET /api/alerts", "GET /api/alerts/{id}", "PUT /api/alerts/{id}",
		"GET /api/commands/{id}", "POST /api/commands",
		"GET /api/enrollments", "POST /api/enrollments/{host_id}/revoke",
		"GET /api/policy", "PUT /api/policy",
		"GET /api/attack-coverage",
		"GET /api/rules",
		"GET /api/session",
	} {
		mux.Handle(p, sessionProtected)
	}
}

// registerUIRoutes serves the embedded React UI at /ui/ and redirects / to /ui/. The bundle
// itself is intentionally unauthenticated: the React app's Login screen is what collects the
// email + password via POST /api/session. The server replies with a HttpOnly session
// cookie and a CSRF token the JS stores in memory. Every subsequent state-changing call
// carries both the cookie (automatic, HttpOnly) and an X-CSRF-Token header. Gating /ui/
// itself behind the Session middleware would make the login page unreachable (chicken/egg).
// The operator surface (everything under /api/* except the agent's host-token
// endpoints and the public enroll/session pair) IS session-gated; the public
// agent and login endpoints sit alongside under /api/* but use their own
// auth.
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
