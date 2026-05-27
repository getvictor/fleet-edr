// fleet-edr-server is the main EDR server that handles event processing, serves the API and UI. Event ingestion can be handled by this
// server or by a separate fleet-edr-ingest instance.
package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
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

const (
	serviceName = "fleet-edr-server"

	// HTTP server timeouts. Read 10s covers a slow agent upload; write 30s and idle 60s bound how long a stuck client holds a connection.
	// Same values as fleet-edr-ingest.
	httpWriteTimeout = 30 * time.Second
	httpIdleTimeout  = 60 * time.Second

	// metricsOfflineThreshold is the "how old is too old" cutoff for the edr.offline.hosts gauge. Mirrored as the UI's offline threshold
	// so what operators see in SigNoz matches what they see on the host page.
	metricsOfflineThreshold = 5 * time.Minute
)

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
		"tls12_allowed", cfg.AllowTLS12,
	)

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

	rulesCtx, err := openRules(ctx, logger, db, cfg, identityCtx, detectionCtx, responseCtx)
	if err != nil {
		return err
	}
	detectionCtx.LoadActive(rulesCtx.ContentService())

	endpointCtx, err := openEndpoint(ctx, logger, db, cfg, responseCtx.Service().Insert, identityCtx)
	if err != nil {
		return err
	}

	// Build the metrics recorder AFTER detectionCtx + endpointCtx exist so the gauge source can read live state from both. Wire it back
	// into detectionCtx via SetMetrics so the engine + intake + pipeline (processttl + retention) all instrument: the recorder + recorder
	// consumer dependency cycle resolves through this two-phase setup.
	metricsRec := metrics.New(
		serverGaugeSource{endpointSvc: endpointCtx.Service(), detectionSvc: detectionCtx.Service()},
		metrics.Options{OfflineThreshold: metricsOfflineThreshold},
	)
	detectionCtx.SetMetrics(metricsRec)

	seedAdmin(ctx, logger, cfg, identityCtx)

	mux := buildMux(muxDeps{
		detectionCtx: detectionCtx,
		endpointCtx:  endpointCtx,
		identityCtx:  identityCtx,
		rulesCtx:     rulesCtx,
		responseCtx:  responseCtx,
		logger:       logger,
	})
	registerUIRoutes(mux, identityCtx.BreakglassUIMiddleware(), logger)

	go runDetection(ctx, detectionCtx, logger)
	go runIdentity(ctx, identityCtx, logger)

	// Only construct the resolver when EDR_TRUSTED_PROXIES is non-empty. httpserver.Build skips installing the middleware on a nil
	// resolver, and httpserver.ClientIP's fallback returns the same peer IP the resolver's empty-list path would return — so this saves
	// one per-request middleware hop in the default deployment (per Copilot review on PR #113).
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
	if err := configureTLS(ctx, logger, srv, cfg); err != nil {
		return err
	}
	return httpserver.RunAndShutdown(ctx, srv, logger)
}

func openIdentity(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
) (*identitybootstrap.Identity, error) {
	identityCtx, err := identitybootstrap.New(ctx, identitybootstrap.Deps{
		DB:                 db,
		Logger:             logger,
		CookieSecure:       cfg.TLSEnabled(),
		AuditReadSampling:  cfg.AuditReadSampling,
		AuditAsyncQueueCap: cfg.AuditAsyncQueueCap,
		SessionSigningKey:  cfg.SessionSigningKey,
		OIDC: identitybootstrap.OIDCDeps{
			Issuer:               cfg.OIDCIssuer,
			ClientID:             cfg.OIDCClientID,
			ClientSecret:         cfg.OIDCClientSecret,
			RedirectURL:          cfg.OIDCRedirectURL,
			Scopes:               cfg.OIDCScopes,
			AllowJITProvisioning: cfg.OIDCAllowJITProvisioning,
			StateCookieTTL:       cfg.OIDCStateCookieTTL,
		},
		Breakglass: identitybootstrap.BreakglassDeps{
			BootstrapTokenTTL: cfg.BreakglassBootstrapTokenTTL,
			IPAllowlist:       cfg.BreakglassIPAllowlist,
			RPID:              cfg.BreakglassRPID,
			RPDisplayName:     cfg.BreakglassRPDisplayName,
			RPOrigins:         cfg.BreakglassRPOrigins,
		},
		SessionIdle:               cfg.SessionIdleTimeout,
		SessionAbsolute:           cfg.SessionAbsoluteTimeout,
		BreakglassSessionIdle:     cfg.BreakglassSessionIdleTimeout,
		BreakglassSessionAbsolute: cfg.BreakglassSessionAbsoluteTimeout,
		ReauthWindow:              cfg.ReauthWindow,
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
		AuthZ:                identityCtx.AuthZ(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "open detection", "err", err)
		return nil, err
	}
	if err := detectionCtx.ApplySchema(ctx); err != nil {
		logger.ErrorContext(ctx, "detection schema", "err", err)
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
		AuthZ:     identityCtx.AuthZ(),
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
	identityCtx *identitybootstrap.Identity,
	detectionCtx *detectionbootstrap.Detection,
	responseCtx *responsebootstrap.Response,
) (*rulesbootstrap.Rules, error) {
	rulesCtx, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:     db,
		Logger: logger,
		RegistryOptions: rulesapi.RegistryOptions{
			SuspiciousExecParentAllowlist: cfg.SuspiciousExecParentAllowlist,
			LaunchAgentAllowlist:          cfg.LaunchAgentAllowlist,
			LaunchDaemonTeamIDAllowlist:   cfg.LaunchDaemonTeamIDAllowlist,
			SudoersWriterAllowlist:        cfg.SudoersWriterAllowlist,
			DisabledRuleIDs:               cfg.DisabledRuleIDs,
		},
		Audit:           identityCtx.AuditRecorder(),
		AuthZ:           identityCtx.AuthZ(),
		CommandInserter: responseCtx.Service().Insert,
		HostLister:      hostListerFromDetection(detectionCtx.Service()),
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

// hostListerFromDetection projects detection's ListHosts (returns the richer HostSummary shape) down to the appcontrol.HostLister
// closure shape ([]string of host_ids). Lives in cmd/main because the projection is part of the rules-context dep wiring, not rules
// itself: rules can't import detection/bootstrap without breaking the bounded-context import rule (ADR-0004).
func hostListerFromDetection(svc detectionapi.Service) func(context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		hosts, err := svc.ListHosts(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, h.HostID)
		}
		return out, nil
	}
}

func openEndpoint(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
	cmdInserter endpointbootstrap.CommandInserter,
	identityCtx *identitybootstrap.Identity,
) (*endpointbootstrap.Endpoint, error) {
	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        cfg.EnrollSecret,
		EnrollRatePerMinute: cfg.EnrollRatePerMin,
		CommandInserter:     cmdInserter,
		Audit:               identityCtx.AuditRecorder(),
		AuthZ:               identityCtx.AuthZ(),
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

func seedAdmin(ctx context.Context, logger *slog.Logger, cfg *config.Config, identityCtx *identitybootstrap.Identity) {
	admin, _, err := identityCtx.Service().SeedAdmin(ctx, os.Stderr)
	if err != nil && !errors.Is(err, identityapi.ErrAlreadySeeded) {
		logger.ErrorContext(ctx, "admin seed failed", "err", err)
		return
	}
	if admin.ID == 0 {
		// SeedAdmin returned ErrAlreadySeeded for a non-canonical
		// pre-existing row. Nothing to do.
		return
	}
	// Phase 4b: print the redemption URL banner when the admin account has no registered WebAuthn credentials yet. Idempotent across
	// container restarts: a fresh deployment prints on every boot until the operator redeems; once the credential is stored, this is
	// silent.
	bg := identityCtx.BreakglassService()
	if bg == nil {
		return
	}
	hasCred, err := bg.HasCredential(ctx, admin.ID)
	if err != nil {
		logger.ErrorContext(ctx, "breakglass credential check failed", "err", err)
		return
	}
	if hasCred {
		return
	}
	// Default the TTL HERE (not when assembling the banner) so the banner reflects the actual TTL the token was issued with.
	// IssueSetupToken's internal default is fine for the DB row, but the banner string has to match. Mirrors the package-side 1h default
	// in breakglass/tokens.go.
	ttl := cfg.BreakglassBootstrapTokenTTL
	if ttl <= 0 {
		ttl = config.DefaultBreakglassBootstrapTokenTTL
	}
	plaintext, _, err := bg.IssueSetupToken(ctx, admin.ID, ttl)
	if err != nil {
		logger.ErrorContext(ctx, "breakglass issue setup token failed", "err", err)
		return
	}
	printBreakglassBanner(ctx, logger, admin.Email, plaintext, ttl, cfg)
}

// printBreakglassBanner writes the redemption URL to stderr in a single write. The plaintext token appears once; the structured log
// line carries the user id only. The URL is built from the first configured RPOrigin (the externally reachable address an operator's
// browser can use); falls back to ListenAddr only when no RPOrigin is set, which is the dev-localhost path.
func printBreakglassBanner(ctx context.Context, logger *slog.Logger, email, plaintext string, ttl time.Duration, cfg *config.Config) {
	url := redemptionURL(cfg, plaintext)
	banner := "" +
		"================================================================\n" +
		"BREAK-GLASS ADMIN SETUP (one-shot redemption URL — open in a browser)\n" +
		"  Email: " + email + "\n" +
		"  URL:   " + url + "\n" +
		"  TTL:   " + ttl.String() + "\n" +
		"================================================================\n"
	if _, err := os.Stderr.WriteString(banner); err != nil {
		logger.ErrorContext(ctx, "write breakglass banner", "err", err)
	}
}

// redemptionURL builds the operator-visible redemption URL. Prefers the first BreakglassRPOrigins entry because that is the URL the
// browser uses to talk to the server (and the WebAuthn engine binds credentials to that origin). Falls back to scheme + ListenAddr
// when no origin is configured — the dev-localhost path.
func redemptionURL(cfg *config.Config, plaintext string) string {
	const path = "/admin/break-glass/setup?token="
	if len(cfg.BreakglassRPOrigins) > 0 {
		origin := strings.TrimRight(cfg.BreakglassRPOrigins[0], "/")
		return origin + path + plaintext
	}
	host := cfg.ListenAddr
	if len(host) > 0 && host[0] == ':' {
		host = "localhost" + host
	}
	// Server is HTTPS-only (issue #140 removed the plaintext-HTTP opt-out), so the redemption URL is always https://.
	return "https://" + host + path + plaintext
}

func configureTLS(ctx context.Context, logger *slog.Logger, srv *http.Server, cfg *config.Config) error {
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
		WriteTimeout: httpWriteTimeout,
		IdleTimeout:  httpIdleTimeout,
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
		"GET /api/audit-events",
		"GET /api/session",
		// Application Control admin surface. rulesCtx.RegisterAuthedRoutes mounts these on apiMux; the outer router needs each
		// path enumerated here so requests reach the session-protected wrapper instead of falling through to the `/` catchall
		// and 302 → /ui/. Surfaced by the step-8 dry-run on PR #158 — the list-policies API returned the SPA's index.html,
		// which the UI fetch parsed as JSON and errored with "Unexpected token '<'". The Phase A close-out follow-on adds the
		// five mutation routes + bulk upsert + cross-policy GET + host-groups CRUD + assignments are all enumerated here. Phase B
		// editable host-group + assignment mutations will replace the 405 handlers at the same routes without churning this list.
		"GET /api/v1/app-control/policies",
		"GET /api/v1/app-control/policies/{id}",
		"POST /api/v1/app-control/policies",
		"PATCH /api/v1/app-control/policies/{id}",
		"DELETE /api/v1/app-control/policies/{id}",
		"POST /api/v1/app-control/policies/{id}/rules",
		"POST /api/v1/app-control/policies/{id}/rules:bulkUpsert",
		"PATCH /api/v1/app-control/rules/{id}",
		"DELETE /api/v1/app-control/rules/{id}",
		"GET /api/v1/app-control/rules",
		// Host-groups + assignments surface. Read endpoints (GET) serve the real seed row; mutation endpoints (POST/PATCH/DELETE)
		// are wired so the wire-shape contract is testable today but return 405 application_control.read_only_in_phase_a
		// (closes tasks 11.4.8 + 11.4.9). Phase B replaces the 405 handlers with real mutation logic without changing routes.
		"GET /api/v1/app-control/host-groups",
		"GET /api/v1/app-control/host-groups/{id}",
		"POST /api/v1/app-control/host-groups",
		"PATCH /api/v1/app-control/host-groups/{id}",
		"DELETE /api/v1/app-control/host-groups/{id}",
		"GET /api/v1/app-control/policies/{id}/assignments",
		"POST /api/v1/app-control/policies/{id}/assignments",
		"DELETE /api/v1/app-control/policies/{id}/assignments/{group_id}",
		// Break-glass reauth ceremony. The handlers are mounted on apiMux via identityCtx.RegisterAuthedRoutes, but the outer
		// router needs each path enumerated here so the session-protected wrapper actually serves them — otherwise requests
		// fall through to the `/` catchall and 302 → /ui/, silently breaking the destructive-action reauth path.
		"POST /api/auth/reauth/challenge", "POST /api/auth/reauth",
	} {
		mux.Handle(p, sessionProtected)
	}
}

func registerUIRoutes(
	mux *http.ServeMux,
	breakglassUIGate func(http.Handler) http.Handler,
	logger *slog.Logger,
) {
	uiDist, err := ui.FS(ui.LiveDirFromEnv())
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

	// /ui/admin/break-glass{,/setup} are the React routes for the break-glass login + setup pages. The breakglass.Handler gates the API
	// endpoints with an IP allowlist and promises the path's existence is concealed from off-list callers; gate the UI shell with the same
	// allowlist so that promise extends to the React layer. Off-list callers see a 404 indistinguishable from "no such path" instead of a
	// fully rendered form they can't actually submit. Register BEFORE the /ui/ catch-all so the more-specific patterns win.
	breakglassUI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveIndex(w, r, uiDist, logger)
	})
	mux.Handle("/ui/admin/break-glass", breakglassUIGate(breakglassUI))
	mux.Handle("/ui/admin/break-glass/setup", breakglassUIGate(breakglassUI))

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

// serveIndex writes the embedded SPA index.html bytes directly. Used as the SPA fallback so React Router handles deep links like
// /ui/hosts/{id} client-side without bouncing through http.FileServer's canonicalisation redirect for index files.
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
