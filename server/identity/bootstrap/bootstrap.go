package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/audit"
	"github.com/fleetdm/edr/server/identity/internal/authz"
	"github.com/fleetdm/edr/server/identity/internal/identities"
	"github.com/fleetdm/edr/server/identity/internal/login"
	"github.com/fleetdm/edr/server/identity/internal/middleware"
	"github.com/fleetdm/edr/server/identity/internal/oidc"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/identity/internal/service"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// Deps bundles what New needs to wire the identity context. cmd/main owns
// the *sqlx.DB handle and shares it across every context's bootstrap.
type Deps struct {
	DB              *sqlx.DB
	Logger          *slog.Logger
	LoginRatePerMin int
	CookieSecure    bool
	// SessionTTL overrides the default session lifetime. Zero means use the
	// sessions package default (12 h).
	SessionTTL time.Duration
	// CleanupInterval overrides how often Run sweeps expired sessions. Zero
	// means use the package default (5 min).
	CleanupInterval time.Duration
	// AuthzShadowMode is the wave-1 rollout flag for the authorization
	// chokepoint. true = evaluate + audit but never deny; false =
	// enforce. The flag is set at boot from EDR_AUTHZ_SHADOW_MODE;
	// flipping it in a running deployment requires a restart in wave
	// 1. A future admin endpoint (or a file-watch) can call
	// Identity.SetAuthzShadowMode atomically; the in-memory flag is
	// already hot-swap-safe via atomic.Bool.
	AuthzShadowMode bool

	// AuditReadSampling is the inclusion probability (0.0-1.0) the
	// chokepoint applies to read-action allow events before submitting
	// them to the async writer. See server/config/config.go for the
	// full semantics; identity passes it through to authz.New.
	AuditReadSampling float64

	// AuditAsyncQueueCap sizes the bounded async-writer buffer. Zero
	// uses the audit package default (8192).
	AuditAsyncQueueCap int

	// OIDC carries the Phase-4a auth knobs. When OIDC.Issuer is empty,
	// the OIDC handler + routes are not constructed (break-glass-only
	// deployment); cfg validation upstream is responsible for refusing
	// to boot if the operator did not opt into that mode.
	OIDC OIDCDeps
	// SessionSigningKey is the HMAC key the OIDC state cookie reuses
	// (per spec). Required when OIDC.Issuer is set; ignored otherwise.
	// 32+ bytes recommended.
	SessionSigningKey []byte
}

// OIDCDeps mirrors the deployment-specific OIDC config the identity
// context needs. Lifted out of Deps so OIDC-related additions don't
// keep widening the parent struct.
type OIDCDeps struct {
	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	Scopes               []string
	AllowJITProvisioning bool
	StateCookieTTL       time.Duration
	HTTPClient           *http.Client // optional; tests inject a fixture
}

const defaultCleanupInterval = 5 * time.Minute

// Identity is the handle cmd/main holds for the identity bounded context. It
// exposes the public Service for cross-context callers (and tests), the
// AuthZ engine for the chokepoint, the middleware factories the operator
// HTTP surface chains, the route registration methods, ApplySchema, and a
// Run method that owns this context's background goroutines.
type Identity struct {
	svc          api.Service
	authzEngine  *authz.Engine
	loginHandler *login.Handler
	oidcHandler  *oidc.Handler // nil in break-glass-only deployments
	auditStore   *audit.Store
	auditHandler *audit.Handler
	auditAsync   *audit.AsyncWriter
	sessionMW    func(http.Handler) http.Handler
	csrfMW       func(http.Handler) http.Handler
	db           *sqlx.DB
	logger       *slog.Logger
	cleanupEvery time.Duration
}

// New wires the identity context. It does NOT apply the schema (call
// ApplySchema for that) and does NOT start any goroutines (call Run).
// Returns an error if Deps is missing required fields. ctx is used to
// compile the AuthZ engine's OPA query at construction time; cancelling
// it before New returns aborts engine setup.
func New(ctx context.Context, deps Deps) (*Identity, error) {
	if deps.DB == nil {
		return nil, errors.New("identity bootstrap: DB is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cleanupEvery := deps.CleanupInterval
	if cleanupEvery <= 0 {
		cleanupEvery = defaultCleanupInterval
	}

	usersStore := users.New(deps.DB)
	sessionsStore := sessions.New(deps.DB, sessions.Options{TTL: deps.SessionTTL})
	rbacStore := rbac.New(deps.DB)
	identitiesStore := identities.New(deps.DB)
	svc := service.New(usersStore, sessionsStore, rbacStore, logger)
	auditStore := audit.New(deps.DB)
	auditAsync := audit.NewAsyncWriter(auditStore, audit.AsyncOptions{
		QueueCap: deps.AuditAsyncQueueCap,
		Logger:   logger,
	})

	authzEngine, err := authz.New(ctx, auditStore, logger, deps.AuthzShadowMode, authz.Options{
		AsyncRead:        auditAsync,
		ReadSamplingRate: deps.AuditReadSampling,
	})
	if err != nil {
		return nil, fmt.Errorf("identity bootstrap: construct authz engine: %w", err)
	}

	oidcHandler, err := buildOIDCHandler(ctx, oidcHandlerDeps{
		deps:       deps,
		logger:     logger,
		sessions:   sessionsStore,
		users:      usersStore,
		identities: identitiesStore,
		rbac:       rbacStore,
		audit:      auditStore,
	})
	if err != nil {
		return nil, err
	}

	return &Identity{
		svc:         svc,
		authzEngine: authzEngine,
		loginHandler: login.New(svc, login.Options{
			RatePerMinute: deps.LoginRatePerMin,
			CookieSecure:  deps.CookieSecure,
			Logger:        logger,
			Audit:         auditStore,
		}),
		oidcHandler:  oidcHandler,
		auditStore:   auditStore,
		auditHandler: audit.NewHandler(auditStore, authzEngine, logger),
		auditAsync:   auditAsync,
		sessionMW:    middleware.Session(svc, logger),
		csrfMW:       middleware.CSRF(logger),
		db:           deps.DB,
		logger:       logger,
		cleanupEvery: cleanupEvery,
	}, nil
}

// oidcHandlerDeps bundles the per-call inputs to buildOIDCHandler.
// Pulled out of the function signature so the call stays under the
// linter's per-call parameter budget without churning through fields
// in two places when the wiring expands.
type oidcHandlerDeps struct {
	deps       Deps
	logger     *slog.Logger
	sessions   *sessions.Store
	users      *users.Store
	identities *identities.Store
	rbac       *rbac.Store
	audit      *audit.Store
}

// buildOIDCHandler constructs the OIDC handler when the deployment
// supplied OIDC config. Returns (nil, nil) for break-glass-only
// deployments — the route registration step skips it. Returns an
// error when the OIDC discovery / verifier setup fails so cmd/main
// refuses to start with an explicit error rather than silently
// falling back.
func buildOIDCHandler(ctx context.Context, in oidcHandlerDeps) (*oidc.Handler, error) {
	if in.deps.OIDC.Issuer == "" {
		return nil, nil
	}
	if len(in.deps.SessionSigningKey) == 0 {
		return nil, errors.New("identity bootstrap: SessionSigningKey is required when OIDC is configured")
	}
	client, err := oidc.New(ctx, oidc.Options{
		Issuer:       in.deps.OIDC.Issuer,
		ClientID:     in.deps.OIDC.ClientID,
		ClientSecret: in.deps.OIDC.ClientSecret,
		RedirectURL:  in.deps.OIDC.RedirectURL,
		Scopes:       in.deps.OIDC.Scopes,
		HTTPClient:   in.deps.OIDC.HTTPClient,
		Logger:       in.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("identity bootstrap: construct OIDC client: %w", err)
	}
	prov := oidc.NewProvisioner(in.deps.DB, in.users, in.identities, in.rbac, in.audit, oidc.ProvisionerOptions{
		AllowJIT: in.deps.OIDC.AllowJITProvisioning,
		Logger:   in.logger,
	})
	return oidc.NewHandler(oidc.HandlerOptions{
		Client:       client,
		Provisioner:  prov,
		Sessions:     in.sessions,
		SigningKey:   in.deps.SessionSigningKey,
		StateTTL:     in.deps.OIDC.StateCookieTTL,
		CookieSecure: in.deps.CookieSecure,
		Audit:        in.audit,
		Logger:       in.logger,
	}), nil
}

// ApplySchema runs the DDL statements identity owns and seeds the
// default tenant + built-in roles. Idempotent: re-running against a
// populated DB is safe (CREATE TABLE IF NOT EXISTS + INSERT IGNORE
// for the seeds).
//
// The cross-context FK fk_alerts_updated_by that used to require
// identity ApplySchema run before detection's was dropped in favour
// of code-level UserExists validation, so call order across contexts
// is no longer load-bearing.
func (i *Identity) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, i.db)
}

// ApplySchema is the package-level form: applies identity's DDL
// against the given DB, then seeds the default tenant and the five
// built-in roles. Used by server/testdb so tests can apply every
// context's schema without faking out each bootstrap's service
// dependencies.
//
// Seed steps run after DDL because they require the tables they
// populate. Both seeds are INSERT IGNORE so re-running on a populated
// DB is a no-op. Tenant seed runs first so that any later code that
// inserts a user (cmd/main's SeedAdmin, the Phase-4 break-glass
// redemption flow) does not trip the users.tenant_id FK.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("identity ApplySchema: db must not be nil")
	}
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("identity schema create: %w", err)
		}
	}
	if err := seed.Tenants(ctx, db); err != nil {
		return fmt.Errorf("identity seed tenants: %w", err)
	}
	if err := seed.Roles(ctx, db); err != nil {
		return fmt.Errorf("identity seed roles: %w", err)
	}
	return nil
}

// Service returns the public Service interface. Used by cross-context
// callers: cmd/main calls Service.SeedAdmin at startup; detection's
// alert-update handler calls Service.UserExists.
func (i *Identity) Service() api.Service { return i.svc }

// SessionMiddleware returns the operator-session middleware. Chain on every
// authed route as Session(CSRF(handler)) so Session pins ctx before CSRF
// reads it.
func (i *Identity) SessionMiddleware() func(http.Handler) http.Handler { return i.sessionMW }

// CSRFMiddleware returns the CSRF middleware. Always inner to Session.
func (i *Identity) CSRFMiddleware() func(http.Handler) http.Handler { return i.csrfMW }

// OIDCEnabled reports whether the OIDC handler was constructed at
// boot. cmd/main uses it to log a single info-level line at startup
// summarising the auth modes the deployment honours.
func (i *Identity) OIDCEnabled() bool { return i.oidcHandler != nil }

// RegisterPublicRoutes wires POST /api/session and DELETE /api/session
// (login + logout). Public because they have no session yet.
func (i *Identity) RegisterPublicRoutes(mux *http.ServeMux) {
	i.loginHandler.RegisterPublicRoutes(mux)
	if i.oidcHandler != nil {
		i.oidcHandler.RegisterPublicRoutes(mux)
	}
}

// RegisterAuthedRoutes wires GET /api/session (who-am-i) and
// GET /api/audit-events (operator-action history). Caller wraps in
// SessionMiddleware + CSRFMiddleware before mounting.
func (i *Identity) RegisterAuthedRoutes(mux *http.ServeMux) {
	i.loginHandler.RegisterAuthedRoutes(mux)
	i.auditHandler.RegisterAuthedRoutes(mux)
}

// AuditRecorder returns the cross-context-callable AuditRecorder.
// Other contexts (response, rules, endpoint) take this as a constructor
// dependency and call Record() at the point an operator action commits;
// see api.AuditRecorder for the interface contract.
func (i *Identity) AuditRecorder() api.AuditRecorder { return i.auditStore }

// AuthZ returns the chokepoint engine. Subsequent per-context
// changes wire this into every privileged handler in detection /
// rules / response / endpoint; today the only consumer is the
// per-context tests that exercise the public api.AuthZ surface.
func (i *Identity) AuthZ() api.AuthZ { return i.authzEngine }

// SetAuthzShadowMode flips the chokepoint's enforcement gate at runtime.
// cmd/main calls this on SIGHUP so an operator can swap shadow mode
// without a restart; tests call it directly. The change is visible to
// the next Allow call (atomic).
func (i *Identity) SetAuthzShadowMode(on bool) { i.authzEngine.SetShadowMode(on) }

// AuthzShadowMode reports the current value of the rollout flag. The
// rollout dashboard reads this via a status endpoint to render
// "shadow / enforcing" on the deny-decision panel.
func (i *Identity) AuthzShadowMode() bool { return i.authzEngine.ShadowMode() }

// Run owns the identity context's background goroutines. Two loops:
// (1) the session-cleanup ticker that sweeps expired session rows,
// (2) the audit async writer that drains chokepoint read-allow events.
// Returns when ctx is cancelled. cmd/main runs it as
// `go func() { _ = identityCtx.Run(ctx) }()`.
//
// The session-cleanup interval is not load-bearing: Session
// middleware already rejects expired rows via the expires_at > NOW()
// filter, so rows that linger for a few extra minutes are harmless.
// That loop is about reclaiming disk, not enforcing security.
//
// The audit async writer is load-bearing on the chokepoint hot
// path: every read-allow audit row routes through it; the loop's
// graceful drain on ctx cancel is the durability bridge to slog when
// the queue empties cleanly.
func (i *Identity) Run(ctx context.Context) error {
	asyncDone := make(chan error, 1)
	go func() { asyncDone <- i.auditAsync.Run(ctx) }()

	t := time.NewTicker(i.cleanupEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Wait for the async writer's graceful drain.
			<-asyncDone
			return nil
		case <-t.C:
			n, err := i.svc.CleanupExpiredSessions(ctx)
			switch {
			case err != nil:
				i.logger.WarnContext(ctx, "session cleanup", "err", err)
			case n > 0:
				i.logger.InfoContext(ctx, "session cleanup removed rows", "count", n)
			}
		}
	}
}
