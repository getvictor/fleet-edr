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
	"github.com/fleetdm/edr/server/identity/internal/login"
	"github.com/fleetdm/edr/server/identity/internal/middleware"
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
	// enforce. cmd/main flips it on SIGHUP via Identity.SetShadowMode.
	AuthzShadowMode bool
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
	auditStore   *audit.Store
	auditHandler *audit.Handler
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
	svc := service.New(usersStore, sessionsStore, rbacStore, logger)
	auditStore := audit.New(deps.DB)

	authzEngine, err := authz.New(ctx, auditStore, logger, deps.AuthzShadowMode)
	if err != nil {
		return nil, fmt.Errorf("identity bootstrap: construct authz engine: %w", err)
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
		auditStore:   auditStore,
		auditHandler: audit.NewHandler(auditStore, logger),
		sessionMW:    middleware.Session(svc, logger),
		csrfMW:       middleware.CSRF(logger),
		db:           deps.DB,
		logger:       logger,
		cleanupEvery: cleanupEvery,
	}, nil
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

// RegisterPublicRoutes wires POST /api/session and DELETE /api/session
// (login + logout). Public because they have no session yet.
func (i *Identity) RegisterPublicRoutes(mux *http.ServeMux) {
	i.loginHandler.RegisterPublicRoutes(mux)
}

// RegisterAuthedRoutes wires GET /api/session (who-am-i) and
// GET /api/audit (operator-action history). Caller wraps in
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

// Run owns the identity context's background goroutines. Today: a ticker
// that sweeps expired session rows. Returns when ctx is cancelled. cmd/main
// runs it as `go func() { _ = identityCtx.Run(ctx) }()`.
//
// The exact interval is not load-bearing: Session middleware already
// rejects expired rows via the expires_at > NOW() filter, so rows that
// linger for a few extra minutes are harmless. This loop is about
// reclaiming disk, not enforcing security.
func (i *Identity) Run(ctx context.Context) error {
	t := time.NewTicker(i.cleanupEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
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
