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
	"github.com/fleetdm/edr/server/identity/internal/breakglass"
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
	DB           *sqlx.DB
	Logger       *slog.Logger
	CookieSecure bool
	// Session timeouts (Phase 5). Per-class idle + absolute caps replace
	// the pre-Phase-5 flat TTL. Zero means use the sessions package
	// defaults: normal 8h idle / 24h absolute, break-glass 15m / 1h.
	SessionIdle               time.Duration
	SessionAbsolute           time.Duration
	BreakglassSessionIdle     time.Duration
	BreakglassSessionAbsolute time.Duration
	// ReauthWindow is the freshness gate for destructive actions. Zero
	// means the sessions package default (30m).
	ReauthWindow time.Duration
	// CleanupInterval overrides how often Run sweeps expired sessions. Zero
	// means use the package default (5 min).
	CleanupInterval time.Duration
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
	// 32+ bytes recommended. Phase 4b reuses the same key for the
	// break-glass challenge cookie.
	SessionSigningKey []byte

	// Breakglass carries the Phase 4b break-glass surface knobs.
	// When Breakglass.RPID is empty AND OIDC is configured, the
	// break-glass surface is not constructed (operator opted out by
	// not setting EDR_BREAKGLASS_RP_ID). When RPID is empty AND OIDC
	// is also unconfigured, the bootstrap layer falls through to a
	// localhost default so dev workflows have a working surface.
	Breakglass BreakglassDeps
}

// BreakglassDeps is the per-deployment configuration the Phase 4b
// break-glass surface needs. Lifted out of Deps so further
// break-glass-related additions don't keep widening the parent
// struct.
type BreakglassDeps struct {
	BootstrapTokenTTL time.Duration
	IPAllowlist       []string
	RPID              string
	RPDisplayName     string
	RPOrigins         []string
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
	svc               api.Service
	authzEngine       *authz.Engine
	loginHandler      *login.Handler
	oidcHandler       *oidc.Handler       // nil in break-glass-only deployments
	breakglassHandler *breakglass.Handler // nil when RPID is unset (opt-out)
	breakglassService *breakglass.Service // exposed for cmd/main first-boot seed
	auditStore        *audit.Store
	auditHandler      *audit.Handler
	auditAsync        *audit.AsyncWriter
	sessionMW         func(http.Handler) http.Handler
	csrfMW            func(http.Handler) http.Handler
	db                *sqlx.DB
	logger            *slog.Logger
	cleanupEvery      time.Duration
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
	sessionsStore := sessions.New(deps.DB, sessions.Options{
		Normal: sessions.Timeouts{
			Idle:     deps.SessionIdle,
			Absolute: deps.SessionAbsolute,
		},
		Breakglass: sessions.Timeouts{
			Idle:     deps.BreakglassSessionIdle,
			Absolute: deps.BreakglassSessionAbsolute,
		},
		ReauthWindow: deps.ReauthWindow,
	})
	rbacStore := rbac.New(deps.DB)
	identitiesStore := identities.New(deps.DB)
	svc := service.New(usersStore, sessionsStore, rbacStore, logger)
	auditStore := audit.New(deps.DB, logger)
	auditAsync := audit.NewAsyncWriter(auditStore, audit.AsyncOptions{
		QueueCap: deps.AuditAsyncQueueCap,
		Logger:   logger,
	})

	authzEngine, err := authz.New(ctx, auditStore, logger, authz.Options{
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

	bgService, bgHandler, err := buildBreakglass(breakglassDeps{
		deps:       deps,
		logger:     logger,
		sessions:   sessionsStore,
		users:      usersStore,
		identities: identitiesStore,
		audit:      auditStore,
		identity:   svc,
	})
	if err != nil {
		return nil, err
	}

	return &Identity{
		svc:         svc,
		authzEngine: authzEngine,
		loginHandler: login.New(svc, login.Options{
			CookieSecure: deps.CookieSecure,
			Logger:       logger,
			Audit:        auditStore,
		}),
		oidcHandler:       oidcHandler,
		breakglassHandler: bgHandler,
		breakglassService: bgService,
		auditStore:        auditStore,
		auditHandler:      audit.NewHandler(auditStore, authzEngine, logger),
		auditAsync:        auditAsync,
		sessionMW:         middleware.Session(svc, logger),
		csrfMW:            middleware.CSRF(logger),
		db:                deps.DB,
		logger:            logger,
		cleanupEvery:      cleanupEvery,
	}, nil
}

// breakglassDeps bundles the per-call inputs to buildBreakglass.
// Same shape pattern as oidcHandlerDeps so future field additions
// don't widen the function signature.
type breakglassDeps struct {
	deps       Deps
	logger     *slog.Logger
	sessions   *sessions.Store
	users      *users.Store
	identities *identities.Store
	audit      *audit.Store
	identity   api.Service // for the Phase 5 reauth POST endpoint
}

// buildBreakglass constructs the break-glass Service + Handler.
// Returns (nil, nil, nil) when the deployment opted out (no RP ID +
// OIDC enabled). Returns an error when the operator partially
// configured the surface — same pattern as the OIDC gate.
func buildBreakglass(in breakglassDeps) (*breakglass.Service, *breakglass.Handler, error) {
	bg := in.deps.Breakglass
	rpID := bg.RPID
	rpOrigins := bg.RPOrigins
	if rpID == "" && len(rpOrigins) == 0 && in.deps.OIDC.Issuer == "" {
		// Dev fallback: neither OIDC nor break-glass explicitly
		// configured. Default to localhost so first-boot works
		// without a long env var prelude. Production is covered by
		// the explicit-config branch below.
		rpID = "localhost"
		rpOrigins = []string{"http://localhost:8088", "http://127.0.0.1:8088"}
	}
	// Reject partial config: an operator who set RPOrigins WITHOUT
	// RPID intended to configure break-glass; silently opting out
	// would brick recovery. Same guard direction as the
	// EDR_OIDC_ISSUER-without-companion check in config.go.
	if rpID == "" && len(rpOrigins) > 0 {
		return nil, nil, errors.New(
			"identity bootstrap: EDR_BREAKGLASS_RP_ORIGINS set without EDR_BREAKGLASS_RP_ID")
	}
	if rpID == "" {
		// OIDC is configured but break-glass is not — operator
		// opted out. Routes will not be mounted AND the seed flow
		// will not issue bootstrap tokens (cmd/main short-circuits
		// when BreakglassService() returns nil). The operator can
		// later opt in by setting EDR_BREAKGLASS_RP_ID; the seed
		// step on the next boot will then issue a token.
		return nil, nil, nil
	}
	if len(rpOrigins) == 0 {
		return nil, nil, errors.New(
			"identity bootstrap: EDR_BREAKGLASS_RP_ID set without EDR_BREAKGLASS_RP_ORIGINS")
	}
	if len(in.deps.SessionSigningKey) == 0 {
		return nil, nil, errors.New(
			"identity bootstrap: SessionSigningKey is required when break-glass is configured")
	}
	displayName := bg.RPDisplayName
	if displayName == "" {
		displayName = "EDR Break-glass"
	}
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     rpOrigins,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("identity bootstrap: webauthn: %w", err)
	}
	tokens := breakglass.NewTokenStore(in.deps.DB)
	credentials := breakglass.NewCredentialStore(in.deps.DB)
	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB:          in.deps.DB,
		Users:       in.users,
		Identities:  in.identities,
		Tokens:      tokens,
		Credentials: credentials,
		Sessions:    in.sessions,
		WebAuthn:    wa,
		Audit:       in.audit,
		Logger:      in.logger,
	})
	allowlist, err := breakglass.NewAllowlist(bg.IPAllowlist)
	if err != nil {
		return nil, nil, fmt.Errorf("identity bootstrap: breakglass allowlist: %w", err)
	}
	h := breakglass.NewHandler(breakglass.HandlerOptions{
		Service:    svc,
		Identity:   in.identity,
		SigningKey: in.deps.SessionSigningKey,
		Allowlist:  allowlist,
		Logger:     in.logger,
	})
	return svc, h, nil
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
		Client:      client,
		Provisioner: prov,
		Sessions:    in.sessions,
		SigningKey:  in.deps.SessionSigningKey,
		StateTTL:    in.deps.OIDC.StateCookieTTL,
		Audit:       in.audit,
		Logger:      in.logger,
	}), nil
}

// ApplySchema runs the DDL statements identity owns and seeds the
// built-in roles. Idempotent: re-running against a populated DB is
// safe (CREATE TABLE IF NOT EXISTS + INSERT IGNORE for the seed).
//
// The cross-context FK fk_alerts_updated_by that used to require
// identity ApplySchema run before detection's was dropped in favour
// of code-level UserExists validation, so call order across contexts
// is no longer load-bearing.
func (i *Identity) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, i.db)
}

// ApplySchema is the package-level form: applies identity's DDL
// against the given DB, then seeds the five built-in roles. Used by
// server/testdb so tests can apply every context's schema without
// faking out each bootstrap's service dependencies.
//
// The roles seed runs after DDL because it requires the tables it
// populates. INSERT IGNORE so re-running on a populated DB is a no-op.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("identity ApplySchema: db must not be nil")
	}
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("identity schema create: %w", err)
		}
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

// RegisterPublicRoutes wires DELETE /api/session (logout) plus the
// pre-auth OIDC + break-glass routes (when configured). Phase 5b
// retired POST /api/session; sessions are now minted by the OIDC
// callback or the break-glass FinishLogin / FinishSetup endpoints.
func (i *Identity) RegisterPublicRoutes(mux *http.ServeMux) {
	i.loginHandler.RegisterPublicRoutes(mux)
	if i.oidcHandler != nil {
		i.oidcHandler.RegisterPublicRoutes(mux)
	}
	if i.breakglassHandler != nil {
		i.breakglassHandler.RegisterPublicRoutes(mux)
	}
}

// BreakglassService exposes the Phase 4b break-glass service so
// cmd/main can call IssueSetupToken on first boot. Returns nil when
// the deployment opted out of the break-glass surface.
func (i *Identity) BreakglassService() *breakglass.Service {
	return i.breakglassService
}

// BreakglassUIMiddleware returns the IP allowlist gate cmd/main wraps
// around the React UI's break-glass subroutes (/ui/admin/break-glass
// and /ui/admin/break-glass/setup). Without this gate, an off-allowlist
// caller could load the React shell at those paths even though the
// API endpoints behind them 404 — defeating the path-concealment
// promise the breakglass.Handler comment makes for /admin/break-glass.
//
// Returns a passthrough middleware (no-op) when the deployment opted
// out of break-glass entirely; the React routes still render but
// hitting them is harmless because no API surface backs them.
func (i *Identity) BreakglassUIMiddleware() func(http.Handler) http.Handler {
	if i.breakglassHandler == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return i.breakglassHandler.AllowlistMiddleware
}

// RegisterAuthedRoutes wires GET /api/session (who-am-i),
// GET /api/audit-events (operator-action history), and the Phase 5
// break-glass reauth POST endpoints. Caller wraps in
// SessionMiddleware + CSRFMiddleware before mounting.
func (i *Identity) RegisterAuthedRoutes(mux *http.ServeMux) {
	i.loginHandler.RegisterAuthedRoutes(mux)
	i.auditHandler.RegisterAuthedRoutes(mux)
	if i.breakglassHandler != nil {
		i.breakglassHandler.RegisterAuthedRoutes(mux)
	}
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
