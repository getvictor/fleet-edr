// fleet-edr-server is the main EDR server that handles event processing, serves the API and UI. Event ingestion can be handled by this
// server or by a separate fleet-edr-ingest instance.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/internal/keyring"
	"github.com/fleetdm/edr/server/apidocs"
	"github.com/fleetdm/edr/server/bootstrap"
	"github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/coordination/leader"
	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/metrics"
	responsebootstrap "github.com/fleetdm/edr/server/response/bootstrap"
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

	// migrationLockName is the MySQL advisory lock that serializes the boot-time schema apply across replicas. Under a rolling
	// upgrade several replicas boot concurrently against one database; holding this lock while applying each context's goose corpus
	// means no two replicas run goose Up at once. It joins the other coordination lock names (edr_retention, edr_process_ttl).
	migrationLockName = "edr_migrations"

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
	)

	db, err := bootstrap.OpenDB(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open db", "err", err)
		return err
	}
	defer func() { _ = db.Close() }()

	// drain is the process-wide graceful-shutdown signal: SIGTERM flips it so /readyz reports 503 and the load balancer drains this
	// replica before RunAndShutdown closes the listener. Shared between the detection intake handler (which serves /readyz) and
	// RunAndShutdown below.
	drain := &httpserver.DrainState{}

	// coord elects a single replica to run the periodic maintenance tasks (retention + process-TTL) via MySQL advisory locks, so
	// they don't run on every replica behind the load balancer, and serializes the boot-time schema apply (openContexts). The
	// processor is intentionally left un-coordinated (it scales via SKIP LOCKED). It shares the main DB pool; each held lock pins one
	// spare connection.
	coord := leader.NewMySQL(db, logger)

	identityCtx, detectionCtx, responseCtx, rulesCtx, endpointCtx, err := openContexts(ctx, logger, db, cfg, coord, drain)
	if err != nil {
		return err
	}

	// The revocation snapshot is the ONLY revocation enforcement on the no-DB verify hot path, so an empty snapshot is "revocation
	// disabled" (absent host => allowed). Fail closed: load it once before serving and treat a failed initial load as fatal rather than
	// serving with an allow-all snapshot. The DB was just exercised by the schema apply above, so a failure here is a real outage, not a
	// transient blip. After the initial load the background ticker keeps it fresh (and retains the previous snapshot on a later blip).
	revSnap := endpointCtx.RevocationSnapshot()
	if rerr := revSnap.Refresh(ctx); rerr != nil {
		return fmt.Errorf("initial revocation snapshot load: %w", rerr)
	}
	go revSnap.Run(ctx, endpointbootstrap.DefaultRevocationRefreshInterval)

	// Service-account revocation snapshot: same posture as the host-token snapshot above. Nil when no service-account signing key was
	// configured. Load once synchronously (fatal on failure: an allow-all snapshot would honour revoked accounts) then refresh in the
	// background.
	if saSnap := identityCtx.ServiceAccountSnapshot(); saSnap != nil {
		if rerr := saSnap.Refresh(ctx); rerr != nil {
			return fmt.Errorf("initial service-account revocation snapshot load: %w", rerr)
		}
		go saSnap.Run(ctx, identitybootstrap.DefaultServiceAccountRevocationRefreshInterval)
	}

	// Build the metrics recorder AFTER detectionCtx + endpointCtx exist so the gauge source can read live state from both. Wire it back
	// into detectionCtx via SetMetrics so the engine + intake + pipeline (processttl + retention) all instrument: the recorder + recorder
	// consumer dependency cycle resolves through this two-phase setup.
	metricsRec := metrics.New(
		serverGaugeSource{endpointSvc: endpointCtx.Service(), detectionSvc: detectionCtx.Service()},
		metrics.Options{OfflineThreshold: metricsOfflineThreshold},
	)
	detectionCtx.SetMetrics(metricsRec)

	seedAdmin(ctx, logger, cfg, identityCtx, coord)

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
	// Converge this replica's detection-config snapshot with mutations made on other replicas (ADR-0010): a peer's exclusion / rule-mode
	// edit only bumps the shared version counter, so without this poll a non-mutating replica would serve a stale config until restart.
	go rulesCtx.Run(ctx)

	// Only construct the resolver when EDR_TRUSTED_PROXIES is non-empty. httpserver.Build skips installing the middleware on a nil
	// resolver, and httpserver.ClientIP's fallback returns the same peer IP the resolver's empty-list path would return, so this saves
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

	srv := newHTTPServer(cfg, mux, logger, clientIPResolver, metricsRec)
	if err := configureTLS(ctx, logger, srv, cfg); err != nil {
		return err
	}
	return httpserver.RunAndShutdown(ctx, srv, logger, drain, cfg.ShutdownDrain)
}

// openContexts wires every bounded context and applies each one's schema under a single MySQL advisory lock. Under a rolling
// upgrade several replicas boot concurrently against one database; holding migrationLockName across the apply serializes them so no
// two run goose Up at once. goose's per-context tracking table makes a second replica's apply a no-op, so every replica still boots.
// The lock is released when this function returns (deferred), well before the server starts serving. See
// docs/adr/0009-migrations-via-goose.md and the "Schema migrations are safe under rolling upgrade" requirement in
// openspec/specs/server-availability/spec.md.
//
// The contexts are returned (rather than assigned inside a coord.WithLock closure) so the compiler's nil-flow analysis can see each
// handle is non-nil on the err == nil path; a closure would hide those assignments behind the lock callback.
func openContexts(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
	coord leader.Coordinator,
	drain *httpserver.DrainState,
) (
	identityCtx *identitybootstrap.Identity,
	detectionCtx *detectionbootstrap.Detection,
	responseCtx *responsebootstrap.Response,
	rulesCtx *rulesbootstrap.Rules,
	endpointCtx *endpointbootstrap.Endpoint,
	err error,
) {
	// One root secret seeds every long-lived server-side key. Build the keyring before acquiring the migration lock so a malformed
	// EDR_SECRET_KEY fails boot fast (config already enforces the >=32-byte floor, so New errors only as a defensive invariant).
	kr, err := keyring.New(cfg.SecretKey)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("build keyring: %w", err)
	}
	// keyring.New holds its own copy of the root, and cfg.SecretKey is not read past this point, so zero the config's copy to
	// minimize how long the raw root secret lives in memory (heap dumps, core files).
	clear(cfg.SecretKey)

	release, err := coord.Lock(ctx, migrationLockName)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	defer release()

	if identityCtx, err = openIdentity(ctx, logger, db, cfg,
		kr.Derive(keyring.SessionSigningKeyLabel), kr.Derive(keyring.OIDCClientSecretLabel),
		kr.Derive(keyring.ServiceAccountTokenSigningLabel)); err != nil {
		return
	}
	if detectionCtx, err = openDetection(ctx, logger, db, cfg, identityCtx, drain.IsDraining, coord); err != nil {
		return
	}
	if responseCtx, err = openResponse(ctx, logger, db, detectionCtx, identityCtx); err != nil {
		return
	}
	if rulesCtx, err = openRules(ctx, logger, db, cfg, identityCtx, detectionCtx, responseCtx); err != nil {
		return
	}
	detectionCtx.LoadActive(rulesCtx.ContentService())
	detectionCtx.SetModeResolver(rulesCtx.DetectionConfigModeResolver())
	endpointCtx, err = openEndpoint(ctx, logger, db, cfg, identityCtx, kr.Derive(keyring.HostTokenSigningLabel))
	return
}

func openIdentity(
	ctx context.Context,
	logger *slog.Logger,
	db *sqlx.DB,
	cfg *config.Config,
	sessionSigningKey []byte,
	oidcSecretKey []byte,
	serviceAccountTokenSigningKey []byte,
) (*identitybootstrap.Identity, error) {
	identityCtx, err := identitybootstrap.New(ctx, identitybootstrap.Deps{
		DB:                            db,
		Logger:                        logger,
		CookieSecure:                  cfg.ExternalTLS(),
		SessionSigningKey:             sessionSigningKey,
		OIDCSecretKey:                 oidcSecretKey,
		ServiceAccountTokenSigningKey: serviceAccountTokenSigningKey,
		OIDC: identitybootstrap.OIDCDeps{
			Issuer:               cfg.OIDCIssuer,
			ClientID:             cfg.OIDCClientID,
			ClientSecret:         cfg.OIDCClientSecret,
			RedirectURL:          cfg.OIDCRedirectURL,
			Scopes:               config.DefaultOIDCScopes(),
			AllowJITProvisioning: cfg.OIDCAllowJITProvisioning,
			DefaultRole:          cfg.OIDCDefaultRole,
			StateCookieTTL:       config.DefaultOIDCStateCookieTTL,
		},
		Breakglass: identitybootstrap.BreakglassDeps{
			BootstrapTokenTTL: cfg.BreakglassBootstrapTokenTTL,
			IPAllowlist:       cfg.BreakglassIPAllowlist,
			RPID:              cfg.BreakglassRPID,
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
	isDraining func() bool,
	coord leader.Coordinator,
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
		ProcessInterval:      config.DefaultProcessInterval,
		ProcessBatch:         config.DefaultProcessBatch,
		StaleProcessTTL:      config.DefaultStaleProcessTTL,
		StaleProcessInterval: config.DefaultStaleProcessInterval,
		RetentionDays:        cfg.RetentionDays,
		RetentionInterval:    config.DefaultRetentionInterval,
		UserExists:           identityCtx.Service().UserExists,
		Audit:                identityCtx.AuditRecorder(),
		AuthZ:                identityCtx.AuthZ(),
		IsDraining:           isDraining,
		Coordinator:          coord,
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
		DB:              db,
		Logger:          logger,
		Audit:           identityCtx.AuditRecorder(),
		AuthZ:           identityCtx.AuthZ(),
		UserEmailByID:   userEmailByIDFromIdentity(identityCtx.Service()),
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

// userEmailByIDFromIdentity adapts identity's Service.GetUser to the rules-context UserEmailByID closure shape used to resolve an
// exclusion's created_by ("user:<id>") to a display email. Lives in cmd/main because, like the host-lister projection, it is part of
// the cross-context dep wiring: rules can't import identity/bootstrap without breaking the bounded-context import rule (ADR-0004).
func userEmailByIDFromIdentity(svc identityapi.Service) func(context.Context, int64) (string, error) {
	return func(ctx context.Context, userID int64) (string, error) {
		u, err := svc.GetUser(ctx, userID)
		if err != nil {
			return "", err
		}
		return u.Email, nil
	}
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
	identityCtx *identitybootstrap.Identity,
	hostTokenSigningKey []byte,
) (*endpointbootstrap.Endpoint, error) {
	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        cfg.EnrollSecret,
		EnrollRatePerMinute: cfg.EnrollRatePerMin,
		Audit:               identityCtx.AuditRecorder(),
		AuthZ:               identityCtx.AuthZ(),
		HostTokenLifetime:   config.DefaultHostTokenLifetime,
		HostTokenSigningKey: hostTokenSigningKey,
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

func seedAdmin(ctx context.Context, logger *slog.Logger, cfg *config.Config, identityCtx *identitybootstrap.Identity, coord leader.Coordinator) {
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
	// Print the redemption URL banner when the admin account has no registered WebAuthn credentials yet. A fresh deployment prints
	// on every boot until the operator redeems; once the credential is stored, this is silent. Under a multi-replica boot the
	// emission is leader-gated below so exactly one replica prints (see the DoOnceIfLeader call).
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
	emit := func(ctx context.Context) error {
		plaintext, _, err := bg.IssueSetupToken(ctx, admin.ID, ttl)
		if err != nil {
			logger.ErrorContext(ctx, "breakglass issue setup token failed", "err", err)
			return err
		}
		printBreakglassBanner(ctx, logger, admin.Email, plaintext, ttl, cfg)
		return nil
	}

	// Gate the banner so a concurrent cluster boot prints exactly one redemption URL rather than one per replica. Fail-open: with
	// no coordinator wired, or if the lock can't be consulted, emit anyway. A missed banner strands the first operator (there is
	// no out-of-band re-issue path), which is strictly worse than a duplicate (both tokens are valid; redeeming one is enough).
	if coord == nil {
		_ = emit(ctx)
		return
	}
	ran, err := coord.DoOnceIfLeader(ctx, "edr_seed_banner", emit)
	switch {
	case err != nil && !ran:
		// The leader gate itself failed (couldn't acquire/consult the lock). Fail open and emit anyway: a missed banner strands
		// the first operator, which is worse than a duplicate.
		logger.WarnContext(ctx, "seed-banner leader gate failed; emitting anyway", "err", err)
		_ = emit(ctx)
	case err != nil:
		// We won the gate and ran emit, but emit itself failed; it already logged the error. Re-emitting would just fail again.
	case !ran:
		logger.InfoContext(ctx, "another replica is emitting the break-glass redemption banner; skipping")
	}
}

// printBreakglassBanner writes the redemption URL to stderr in a single write. The plaintext token appears once; the structured log
// line carries the user id only. The URL is built from the first configured RPOrigin (the externally reachable address an operator's
// browser can use); falls back to ListenAddr only when no RPOrigin is set, which is the dev-localhost path.
func printBreakglassBanner(ctx context.Context, logger *slog.Logger, email, plaintext string, ttl time.Duration, cfg *config.Config) {
	url := redemptionURL(cfg, plaintext)
	banner := "" +
		"================================================================\n" +
		"BREAK-GLASS ADMIN SETUP (one-shot redemption URL: open in a browser)\n" +
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
// when no origin is configured: the dev-localhost path.
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
	if cfg.TLSTerminatedByProxy {
		// Leave srv.TLSConfig nil so RunAndShutdown serves plaintext HTTP. Config validation already guaranteed no cert files are
		// set in this mode. Warn loudly so an operator who set the flag by accident (no proxy actually in front) sees that the
		// data plane is plaintext on the bind address.
		logger.WarnContext(ctx, "serving plaintext HTTP: EDR_TLS_TERMINATED_BY_PROXY=1 is set; this is only safe behind a "+
			"TLS-terminating proxy (PaaS edge, ALB, nginx). Do not expose this bind address directly to agents or the internet.",
			"listen_addr", cfg.ListenAddr)
		return nil
	}
	return httpserver.ConfigureTLS(ctx, srv, httpserver.TLSOptions{
		CertFile: cfg.TLSCertFile,
		KeyFile:  cfg.TLSKeyFile,
		Logger:   logger,
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

func newHTTPServer(
	cfg *config.Config,
	mux *http.ServeMux,
	logger *slog.Logger,
	clientIPResolver *httpserver.ClientIPResolver,
	metricsRec *metrics.Recorder,
) *http.Server {
	handler := httpserver.Build(mux, httpserver.Options{
		Logger:      logger,
		ServiceName: serviceName,
		// HSTS keys on the client-facing scheme: emit it when a front proxy terminates TLS too, since the browser reaches us
		// over HTTPS. Safe under the accidental-flag case because browsers ignore HSTS received over a direct plain-HTTP hit.
		TLSEnabled:       cfg.ExternalTLS(),
		ClientIPResolver: clientIPResolver,
		Metrics:          metricsRec,
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
	hostMux.Handle("POST /api/token/refresh", d.endpointCtx.TokenRefreshHandler())
	d.responseCtx.RegisterAgentRoutes(hostMux)
	hostProtected := hostTokenMW(hostMux)
	for _, p := range []string{
		"POST /api/events",
		"POST /api/token/refresh",
		"GET /api/commands",
		"PUT /api/commands/{id}",
	} {
		mux.Handle(p, hostProtected)
	}
}

func registerSessionRoutes(mux *http.ServeMux, d muxDeps) {
	sessionMW := d.identityCtx.SessionMiddleware()
	csrfMW := d.identityCtx.CSRFMiddleware()
	// The operator API accepts two transports (ADR-0013): a service-account bearer token (verified statelessly, CSRF-exempt) or a
	// browser cookie session + CSRF. APIAuthMiddleware composes both and pins an actor either way. It is nil only in minimal wiring
	// with no service-account signing key, in which case fall back to the cookie-only chain.
	protect := func(h http.Handler) http.Handler {
		if apiAuth := d.identityCtx.APIAuthMiddleware(); apiAuth != nil {
			return apiAuth(h)
		}
		return sessionMW(csrfMW(h))
	}
	mountAuthed(mux, protect, func(r httpserver.Router) {
		d.detectionCtx.RegisterAuthedRoutes(r)
		d.rulesCtx.RegisterAuthedRoutes(r)
		d.endpointCtx.RegisterAuthedRoutes(r)
		d.responseCtx.RegisterAuthedRoutes(r)
		d.identityCtx.RegisterAuthedRoutes(r)
	})
}

// mountAuthed derives the session-protected allowlist instead of hand-maintaining it (issue #463). It runs register against a
// RecordingRouter over a fresh apiMux, wraps apiMux in protect (the session/bearer auth chain), and mounts EXACTLY the recorded
// patterns on outer. Because the mounted set is whatever register actually registered, a new authed route is allowlisted
// automatically: a route can no longer be registered-but-not-mounted, so it can never fall through to the `/` SPA catch-all and 302
// (which the UI then parsed as JSON). The bug bit twice before deriving (app-control #158, SSO #375). The credential-exchange token
// endpoint (POST /api/oauth/token) is intentionally NOT here; it is a public route registered via RegisterPublicRoutes.
func mountAuthed(outer *http.ServeMux, protect func(http.Handler) http.Handler, register func(httpserver.Router)) {
	apiMux := http.NewServeMux()
	rec := httpserver.NewRecordingRouter(apiMux)
	register(rec)
	sessionProtected := protect(apiMux)
	for _, p := range rec.Patterns() {
		outer.Handle(p, sessionProtected)
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
