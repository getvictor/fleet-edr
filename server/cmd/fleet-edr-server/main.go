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
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fleetdm/edr/server/admin"
	"github.com/fleetdm/edr/server/api"
	apidocs "github.com/fleetdm/edr/server/api/docs"
	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/bootstrap"
	"github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/detection/rules"
	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/metrics"
	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/processor"
	"github.com/fleetdm/edr/server/processttl"
	"github.com/fleetdm/edr/server/retention"
	"github.com/fleetdm/edr/server/seed"
	"github.com/fleetdm/edr/server/session"
	"github.com/fleetdm/edr/server/sessions"
	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/ui"
	"github.com/fleetdm/edr/server/users"
)

// serverGaugeSource adapts our enrollment + store handles to the metrics.GaugeSource
// interface. Lives here (not in the metrics package) so the metrics package stays
// free of MySQL dependencies and testable without a real DB.
type serverGaugeSource struct {
	enroll *enrollment.Store
	store  *store.Store
}

func (g serverGaugeSource) EnrolledHosts(ctx context.Context) (int, error) {
	return g.enroll.CountActive(ctx)
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

	s, err := store.New(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		return err
	}
	defer func() { _ = s.Close() }()

	build := ingest.BuildInfo{Version: version, Commit: commit, BuildTime: buildTime}
	ingestHandler := ingest.New(s, logger, build)
	builder := graph.NewBuilder(s, logger)
	det := detection.NewEngine(s, logger)
	for _, r := range rules.All(rules.RegistryOptions{
		SuspiciousExecParentAllowlist: cfg.SuspiciousExecParentAllowlist,
		LaunchAgentAllowlist:          cfg.LaunchAgentAllowlist,
		LaunchDaemonTeamIDAllowlist:   cfg.LaunchDaemonTeamIDAllowlist,
		SudoersWriterAllowlist:        cfg.SudoersWriterAllowlist,
	}) {
		det.Register(r)
	}
	proc := processor.New(s, builder, det, logger, cfg.ProcessInterval, cfg.ProcessBatch)

	q := graph.NewQuery(s)
	apiHandler := api.New(q, s, logger)

	enrollStore := enrollment.NewStore(s.DB())
	policyStore := policy.New(s.DB())
	userStore := users.New(s.DB())
	sessionStore := sessions.New(s.DB(), sessions.Options{})

	// Phase 4: OTel metrics recorder. Instruments register against the global meter
	// provider wired by observability.Init; counters, histograms, and observable
	// gauges flow through the same OTLP pipeline as traces + logs, so SigNoz (or any
	// OTLP backend) sees them without a separate scrape endpoint. Gauge source
	// queries live state on each collection via the enrollStore + s adapter.
	metricsRec := metrics.New(
		serverGaugeSource{enroll: enrollStore, store: s},
		metrics.Options{OfflineThreshold: 5 * time.Minute},
	)
	ingestHandler.SetMetrics(metricsRec)
	det.SetMetrics(metricsRec)

	// Phase 3: seed the first admin before we bind the HTTP listener. If the operator
	// is watching, they capture the printed password at boot; if they miss it they can
	// restart and re-seed by deleting the admin row. Never fatal — a seed failure is
	// logged but the server still boots (operator can run migrations by hand).
	if _, _, err := seed.Admin(ctx, userStore, logger, os.Stderr); err != nil {
		logger.ErrorContext(ctx, "admin seed failed", "err", err)
	}

	enrollHandler := enrollment.NewHandler(enrollStore, enrollment.Options{
		EnrollSecret:  cfg.EnrollSecret,
		RatePerMinute: cfg.EnrollRatePerMin,
		Logger:        logger,
		PolicyStore:   policyStore,
		CommandStore:  s,
	})
	adminHandler := admin.New(enrollStore, policyStore, s, catalogFromEngine(det), logger)
	sessionHandler := session.New(userStore, sessionStore, session.Options{
		RatePerMinute: cfg.LoginRatePerMin,
		CookieSecure:  cfg.TLSEnabled(),
		Logger:        logger,
	})

	mux := buildMux(muxDeps{
		ingestHandler:  ingestHandler,
		enrollHandler:  enrollHandler,
		sessionHandler: sessionHandler,
		apiHandler:     apiHandler,
		adminHandler:   adminHandler,
		enrollStore:    enrollStore,
		sessionStore:   sessionStore,
		logger:         logger,
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
	go runSessionCleanup(ctx, sessionStore, logger)
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

// runSessionCleanup sweeps expired session rows on a 5-minute cadence. The
// exact interval is not load-bearing: Session middleware already rejects
// expired rows via the `expires_at > NOW()` filter, so rows that linger for a
// few extra minutes are harmless — this loop is about reclaiming disk, not
// enforcing security.
func runSessionCleanup(ctx context.Context, sessionStore *sessions.Store, logger *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := sessionStore.CleanupExpired(ctx)
			switch {
			case err != nil:
				logger.WarnContext(ctx, "session cleanup", "err", err)
			case n > 0:
				logger.InfoContext(ctx, "session cleanup removed rows", "count", n)
			}
		}
	}
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

// muxDeps bundles the handlers + stores the HTTP mux assembly needs, so buildMux takes
// a single argument and new middleware layers don't keep widening the signature.
type muxDeps struct {
	ingestHandler  *ingest.Handler
	enrollHandler  *enrollment.Handler
	sessionHandler *session.Handler
	apiHandler     *api.Handler
	adminHandler   *admin.Handler
	enrollStore    *enrollment.Store
	sessionStore   *sessions.Store
	logger         *slog.Logger
}

// buildMux composes the HTTP surface out of three authorization domains:
//   - public:  /livez, /readyz, /health, POST /api/enroll, POST /api/session,
//     DELETE /api/session (logout is best-effort and idempotent;
//     tolerating an unknown session avoids forcing a session probe
//     before a logout request)
//   - host:    POST /api/events, GET /api/commands, PUT /api/commands/{id}
//     (wrapped in authn.HostToken — the agent polls for + reports on its own commands)
//   - session: /api/hosts/**, /api/alerts/**, /api/enrollments/**, /api/policy,
//     /api/attack-coverage, /api/rules, POST /api/commands, GET /api/commands/{id},
//     GET /api/session (wrapped in authn.Session; unsafe methods additionally
//     gated by authn.CSRF)
//
// Middleware is applied per-handler at registration time so one mux serves the whole
// surface instead of chaining multiple servers.
func buildMux(d muxDeps) *http.ServeMux {
	mux := http.NewServeMux()
	d.ingestHandler.RegisterHealthRoutes(mux)
	d.enrollHandler.RegisterRoutes(mux)
	// POST /api/session is public — there is no session yet. The session handler
	// does its own rate-limit + audit log so it does not need a wrapper.
	d.sessionHandler.RegisterPublicRoutes(mux)
	// Self-hosted Redoc at /api/docs (the matching spec at /api/openapi.yaml).
	// Public on purpose: same content is on the GitHub release page and
	// procurement teams browse it pre-eval.
	apidocs.RegisterRoutes(mux)

	registerHostRoutes(mux, d)
	registerSessionRoutes(mux, d)
	return mux
}

// registerHostRoutes wires the host-token protected agent endpoints onto mux. A
// dedicated sub-mux keeps api.Handler routes (GET/PUT commands) scoped together with
// the ingest handler under a single HostToken middleware.
func registerHostRoutes(mux *http.ServeMux, d muxDeps) {
	hostTokenMW := authn.HostToken(d.enrollStore, d.logger)
	hostMux := http.NewServeMux()
	hostMux.Handle("POST /api/events", d.ingestHandler.IngestHandler())
	hostMux.HandleFunc("GET /api/commands", d.apiHandler.ListCommands)
	hostMux.HandleFunc("PUT /api/commands/{id}", d.apiHandler.UpdateCommandStatus)
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
	sessionMW := authn.Session(d.sessionStore, d.logger)
	csrfMW := authn.CSRF(d.logger)
	apiMux := http.NewServeMux()
	d.apiHandler.RegisterRoutes(apiMux)
	d.adminHandler.RegisterRoutes(apiMux)
	d.sessionHandler.RegisterAuthedRoutes(apiMux)
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

// engineCatalogAdapter bridges *detection.Engine.Catalog (returning
// detection.RuleMetadata) to admin.Cataloger (which expects
// []admin.RuleMetadata). The two types are deliberately duplicated — see
// admin.RuleMetadata for the rationale — so this copy is the conversion
// boundary.
type engineCatalogAdapter struct{ engine *detection.Engine }

func (a engineCatalogAdapter) Catalog() []admin.RuleMetadata {
	src := a.engine.Catalog()
	out := make([]admin.RuleMetadata, len(src))
	for i, r := range src {
		cfg := make([]admin.RuleConfig, len(r.Doc.Config))
		for j, c := range r.Doc.Config {
			cfg[j] = admin.RuleConfig{
				EnvVar:      c.EnvVar,
				Type:        c.Type,
				Default:     c.Default,
				Description: c.Description,
			}
		}
		out[i] = admin.RuleMetadata{
			ID:         r.ID,
			Techniques: r.Techniques,
			Doc: admin.RuleDoc{
				Title:          r.Doc.Title,
				Summary:        r.Doc.Summary,
				Description:    r.Doc.Description,
				Severity:       r.Doc.Severity,
				EventTypes:     r.Doc.EventTypes,
				FalsePositives: r.Doc.FalsePositives,
				Limitations:    r.Doc.Limitations,
				Config:         cfg,
			},
		}
	}
	return out
}

func catalogFromEngine(e *detection.Engine) admin.Cataloger {
	return engineCatalogAdapter{engine: e}
}
