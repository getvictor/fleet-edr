package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/appconfig"
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
	"github.com/fleetdm/edr/server/identity/internal/ssoadmin"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/identity/internal/users"
	identitymigrations "github.com/fleetdm/edr/server/identity/migrations"
	"github.com/fleetdm/edr/server/migrations/runner"
)

// Deps bundles what New needs to wire the identity context. cmd/main owns
// the *sqlx.DB handle and shares it across every context's bootstrap.
type Deps struct {
	DB           *sqlx.DB
	Logger       *slog.Logger
	CookieSecure bool
	// Session timeouts: per-class idle + absolute caps. Zero means use the sessions package defaults: normal 8h idle / 24h absolute,
	// break-glass 15m / 1h.
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
	// AuditReadSampling is the inclusion probability (0.0-1.0) the chokepoint applies to read-action allow events before submitting them
	// to the async writer. See server/config/config.go for the full semantics; identity passes it through to authz.New.
	AuditReadSampling float64

	// AuditAsyncQueueCap sizes the bounded async-writer buffer. Zero
	// uses the audit package default (8192).
	AuditAsyncQueueCap int

	// OIDC carries the OIDC auth knobs. When OIDC.Issuer is empty, the OIDC handler + routes are not constructed (break-glass-only
	// deployment); cfg validation upstream is responsible for refusing to boot if the operator did not opt into that mode.
	OIDC OIDCDeps
	// SessionSigningKey is the HMAC key the OIDC state cookie reuses (per spec). Required when OIDC.Issuer is set; ignored otherwise.
	// 32+ bytes recommended. The break-glass challenge cookie reuses the same key.
	SessionSigningKey []byte
	// OIDCSecretKey seals the stored OIDC client secret at rest (keyring label edr/oidc/client-secret/v1). Required to build the
	// runtime OIDC config store; when empty (minimal test wiring) the OIDC handler is not constructed.
	OIDCSecretKey []byte

	// Breakglass carries the break-glass surface knobs. When Breakglass.RPID is empty AND OIDC is configured, the break-glass surface is
	// not constructed (operator opted out by not setting EDR_BREAKGLASS_RP_ID). When RPID is empty AND OIDC is also unconfigured, the
	// bootstrap layer falls through to a localhost default so dev workflows have a working surface.
	Breakglass BreakglassDeps
}

// BreakglassDeps is the per-deployment configuration the break-glass surface needs. Lifted out of Deps so further break-glass-related
// additions don't keep widening the parent struct.
type BreakglassDeps struct {
	BootstrapTokenTTL time.Duration
	IPAllowlist       []string
	RPID              string
	RPDisplayName     string
	RPOrigins         []string
}

// OIDCDeps mirrors the deployment-specific OIDC config the identity context needs. Lifted out of Deps so OIDC-related additions don't
// keep widening the parent struct.
type OIDCDeps struct {
	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	Scopes               []string
	AllowJITProvisioning bool
	// DefaultRole is the role a JIT-provisioned OIDC user is bound to. Empty falls through to the provisioner default (`analyst`).
	DefaultRole    string
	StateCookieTTL time.Duration
	HTTPClient     *http.Client // optional; tests inject a fixture
}

const defaultCleanupInterval = 5 * time.Minute

// Identity is the handle cmd/main holds for the identity bounded context. It exposes the public Service for cross-context callers
// (and tests), the AuthZ engine for the chokepoint, the middleware factories the operator HTTP surface chains, the route registration
// methods, ApplySchema, and a Run method that owns this context's background goroutines.
type Identity struct {
	svc               api.Service
	authzEngine       *authz.Engine
	loginHandler      *login.Handler
	oidcHandler       *oidc.Handler       // nil only when no signing/secret key was provided (minimal test wiring)
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
	// ssoStore is the durable OIDC config store (nil when the OIDC handler was not built). oidcSeed carries the env OIDC values used to
	// seed the store on first boot; oidcConfiguredAtBoot records whether a usable config existed after seeding, for OIDCEnabled.
	ssoStore             *ssoconfig.Store
	appConfigStore       *appconfig.Store
	ssoAdminHandler      *ssoadmin.Handler // nil when the OIDC handler was not built (no signing/secret key)
	oidcSeed             OIDCDeps
	oidcConfiguredAtBoot bool
}

// New wires the identity context. It does NOT apply the schema (call ApplySchema for that) and does NOT start any goroutines (call
// Run). Returns an error if Deps is missing required fields. ctx is used to compile the AuthZ engine's OPA query at construction time;
// cancelling it before New returns aborts engine setup.
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

	// appConfigStore holds the deployment's general settings document (external URL today). It is consumed by the OIDC resolver (redirect
	// derivation) and the SSO admin API, and seeded from env at ApplySchema time.
	appConfigStore := appconfig.New(deps.DB)

	oidcHandler, ssoStore, err := buildOIDCHandler(oidcHandlerDeps{
		deps:       deps,
		logger:     logger,
		sessions:   sessionsStore,
		users:      usersStore,
		identities: identitiesStore,
		rbac:       rbacStore,
		audit:      auditStore,
		appCfg:     appConfigStore,
	})
	if err != nil {
		return nil, err
	}

	// The SSO admin API (read/update/test-connection) shares the config + app-config stores with the resolver; built only when the
	// OIDC config store exists (i.e. keys were supplied).
	var ssoAdminHandler *ssoadmin.Handler
	if ssoStore != nil {
		oidcHTTPClient := deps.OIDC.HTTPClient
		ssoAdminHandler = ssoadmin.NewHandler(ssoStore, appConfigStore, authzEngine, auditStore,
			func(ctx context.Context, issuer string) error { return oidc.Probe(ctx, issuer, oidcHTTPClient) }, logger)
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
			Permissions:  authzEngine,
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
		ssoStore:          ssoStore,
		appConfigStore:    appConfigStore,
		ssoAdminHandler:   ssoAdminHandler,
		oidcSeed:          deps.OIDC,
	}, nil
}

// breakglassDeps bundles the per-call inputs to buildBreakglass. Same shape pattern as oidcHandlerDeps so future field additions don't
// widen the function signature.
type breakglassDeps struct {
	deps       Deps
	logger     *slog.Logger
	sessions   *sessions.Store
	users      *users.Store
	identities *identities.Store
	audit      *audit.Store
	identity   api.Service // for the reauth POST endpoint
}

// buildBreakglass constructs the break-glass Service + Handler. Returns (nil, nil, nil) when the deployment opted out (no RP ID + OIDC
// enabled). Returns an error when the operator partially configured the surface, following the same pattern as the OIDC gate.
func buildBreakglass(in breakglassDeps) (*breakglass.Service, *breakglass.Handler, error) {
	bg := in.deps.Breakglass
	rpID := bg.RPID
	rpOrigins := bg.RPOrigins
	if rpID == "" && len(rpOrigins) == 0 && in.deps.OIDC.Issuer == "" {
		// Dev fallback: neither OIDC nor break-glass explicitly configured. Default to localhost so first-boot works without a
		// long env var prelude. Production is covered by the explicit-config branch below.
		rpID = "localhost"
		rpOrigins = []string{"http://localhost:8088", "http://127.0.0.1:8088"}
	}
	// Reject partial config: an operator who set RPOrigins WITHOUT RPID intended to configure break-glass; silently opting out would brick
	// recovery. Same guard direction as the EDR_OIDC_ISSUER-without-companion check in config.go.
	if rpID == "" && len(rpOrigins) > 0 {
		return nil, nil, errors.New(
			"identity bootstrap: EDR_BREAKGLASS_RP_ORIGINS set without EDR_BREAKGLASS_RP_ID")
	}
	if rpID == "" {
		// OIDC is configured but break-glass is not: the operator opted out. Routes will not be mounted AND the seed flow will not issue
		// bootstrap tokens (cmd/main short-circuits when BreakglassService() returns nil). The operator can later opt in by setting
		// EDR_BREAKGLASS_RP_ID; the seed step on the next boot will then issue a token.
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

// oidcHandlerDeps bundles the per-call inputs to buildOIDCHandler. Pulled out of the function signature so the call stays under the
// linter's per-call parameter budget without churning through fields in two places when the wiring expands.
type oidcHandlerDeps struct {
	deps       Deps
	logger     *slog.Logger
	sessions   *sessions.Store
	users      *users.Store
	identities *identities.Store
	rbac       *rbac.Store
	audit      *audit.Store
	appCfg     *appconfig.Store
}

// buildOIDCHandler constructs the runtime-reconfigurable OIDC handler plus the durable config store it reads from. Unlike the wave-1
// boot-once client, this builds no provider at boot: the resolver discovers and caches the provider on the first login from whatever
// configuration the store holds, and rebuilds it on a config change (no restart). It returns (nil, nil, nil) only when no signing or
// secret key was supplied (minimal test wiring), in which case OIDC is simply unavailable; production always supplies both keys.
//
// The returned *ssoconfig.Store is retained by New so the ApplySchema step can seed the row from env on first boot and so OIDCEnabled
// can report config presence.
func buildOIDCHandler(in oidcHandlerDeps) (*oidc.Handler, *ssoconfig.Store, error) {
	if len(in.deps.SessionSigningKey) == 0 || len(in.deps.OIDCSecretKey) == 0 {
		return nil, nil, nil
	}
	sealer, err := ssoconfig.NewSealer(in.deps.OIDCSecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("identity bootstrap: build OIDC secret sealer: %w", err)
	}
	store := ssoconfig.New(in.deps.DB, sealer)

	// The resolver reads the decrypted connection config per login; ErrNotFound (no config yet) maps to oidc.ErrNotConfigured so the
	// login route returns a directed "SSO not configured" response instead of a 500.
	resolver := oidc.NewResolver(func(ctx context.Context) (oidc.ProviderConfig, error) {
		c, err := store.GetDecrypted(ctx)
		if errors.Is(err, ssoconfig.ErrNotFound) {
			return oidc.ProviderConfig{}, oidc.ErrNotConfigured
		}
		if err != nil {
			return oidc.ProviderConfig{}, err
		}
		// The redirect URI is derived from the deployment external URL, which lives in the appconfig document and changes independently
		// of oidc_config; fold both versions into the cache stamp so an external-URL edit rebuilds the client too.
		appCfg, appVersion, err := in.appCfg.Get(ctx)
		if err != nil {
			return oidc.ProviderConfig{}, err
		}
		return oidc.ProviderConfig{
			Issuer:       c.Issuer,
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  ssoconfig.RedirectURLFor(appCfg.ExternalURL),
			Scopes:       c.Scopes,
			Stamp:        fmt.Sprintf("%d.%d", c.Version, appVersion),
		}, nil
	}, in.deps.OIDC.HTTPClient, in.logger)

	// The provisioner reads the JIT toggle + default role from the same store at provision time, so a UI edit of either applies on the
	// next sign-in. No stored config means JIT is off (unknown subjects are denied), matching the wave-1 default.
	prov := oidc.NewProvisioner(in.deps.DB, in.users, in.identities, in.rbac, in.audit, oidc.ProvisionerOptions{
		Logger: in.logger,
		PolicyFn: func(ctx context.Context) (allowJIT bool, defaultRole string, err error) {
			c, err := store.Get(ctx)
			if errors.Is(err, ssoconfig.ErrNotFound) {
				return false, "", nil
			}
			if err != nil {
				return false, "", err
			}
			return c.JITEnabled, c.DefaultRole, nil
		},
	})

	return oidc.NewHandler(oidc.HandlerOptions{
		Resolve:     resolver.Current,
		Provisioner: prov,
		Sessions:    in.sessions,
		SigningKey:  in.deps.SessionSigningKey,
		StateTTL:    in.deps.OIDC.StateCookieTTL,
		Audit:       in.audit,
		Logger:      in.logger,
	}), store, nil
}

// ApplySchema applies identity's goose migration corpus and seeds the
// built-in roles. Idempotent: re-running against a populated DB is
// safe (goose skips applied versions + INSERT IGNORE for the seed).
//
// The cross-context FK fk_alerts_updated_by that used to require
// identity ApplySchema run before detection's was dropped in favour
// of code-level UserExists validation, so call order across contexts
// is no longer load-bearing.
func (i *Identity) ApplySchema(ctx context.Context) error {
	if err := ApplySchema(ctx, i.db); err != nil {
		return err
	}
	return i.seedOIDCConfigFromEnv(ctx)
}

// seedOIDCConfigFromEnv implements the env-seeds / DB-governs precedence (issue #375). On first boot, when no stored OIDC config row
// exists and the EDR_OIDC_* block is set, it seeds the row from those env values so existing env-only deployments keep working
// unchanged across the upgrade. When a row already exists, env values are inert and only logged. It runs after the schema is applied
// (the oidc_config table must exist) and records whether a usable config is present for OIDCEnabled. No-op when the OIDC handler was
// not built (no signing/secret key).
func (i *Identity) seedOIDCConfigFromEnv(ctx context.Context) error {
	if i.ssoStore == nil {
		return nil
	}
	_, err := i.ssoStore.Get(ctx)
	switch {
	case err == nil:
		i.oidcConfiguredAtBoot = true
		if i.oidcSeed.Issuer != "" {
			i.logger.InfoContext(ctx, "EDR_OIDC_* env vars present but a stored OIDC config exists; env values are inert (stored config governs)")
		}
		return nil
	case !errors.Is(err, ssoconfig.ErrNotFound):
		return fmt.Errorf("identity bootstrap: read OIDC config: %w", err)
	}
	// No stored row. Seed from env when the block is set; otherwise leave OIDC unconfigured (admin configures it via the UI after a
	// break-glass login).
	if i.oidcSeed.Issuer == "" {
		return nil
	}
	defaultRole := i.oidcSeed.DefaultRole
	if defaultRole == "" {
		defaultRole = oidc.DefaultJITRole
	}
	secret := i.oidcSeed.ClientSecret
	if err := i.ssoStore.Upsert(ctx, ssoconfig.UpsertInput{
		Issuer:      i.oidcSeed.Issuer,
		ClientID:    i.oidcSeed.ClientID,
		NewSecret:   &secret,
		Scopes:      i.oidcSeed.Scopes,
		JITEnabled:  i.oidcSeed.AllowJITProvisioning,
		DefaultRole: defaultRole,
		UpdatedBy:   nil,
	}); err != nil {
		return fmt.Errorf("identity bootstrap: seed OIDC config from env: %w", err)
	}
	// The external URL is deployment-level and lives in the appconfig document. EDR_OIDC_REDIRECT_URL is the full callback URL; recover
	// the base by trimming a trailing callback path (best-effort). Seed it only when the app_config document has no external URL yet, so
	// a later UI edit is never clobbered on restart.
	externalURL := strings.TrimSuffix(strings.TrimRight(i.oidcSeed.RedirectURL, "/"), ssoconfig.CallbackPath)
	if externalURL != "" {
		if cur, _, err := i.appConfigStore.Get(ctx); err != nil {
			return fmt.Errorf("identity bootstrap: read app config: %w", err)
		} else if cur.ExternalURL == "" {
			cur.ExternalURL = externalURL
			if err := i.appConfigStore.Put(ctx, cur, nil); err != nil {
				return fmt.Errorf("identity bootstrap: seed external URL from env: %w", err)
			}
		}
	}
	i.oidcConfiguredAtBoot = true
	i.logger.InfoContext(ctx, "seeded OIDC config from EDR_OIDC_* env vars (first boot); the stored config now governs and survives restarts")
	return nil
}

// ApplySchema is the package-level form: applies identity's goose migration corpus against the given DB, then seeds the five
// built-in roles. Used by server/testdb so tests can apply every context's schema without faking out each bootstrap's service
// dependencies.
//
// The roles seed runs after the migrations because it requires the tables they create. INSERT IGNORE so re-running on a populated
// DB is a no-op; goose itself skips already-applied versions.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("identity ApplySchema: db must not be nil")
	}
	if err := runner.Up(ctx, db, identitymigrations.FS, runner.Options{
		Context:   "identity",
		TableName: "identity_goose_db_version",
	}); err != nil {
		return err
	}
	if err := seed.Roles(ctx, db); err != nil {
		return fmt.Errorf("identity seed roles: %w", err)
	}
	return nil
}

// Service returns the public Service interface. Used by cross-context callers: cmd/main calls Service.SeedAdmin at startup;
// detection's alert-update handler calls Service.UserExists.
func (i *Identity) Service() api.Service { return i.svc }

// SessionMiddleware returns the operator-session middleware. Chain on every authed route as Session(CSRF(handler)) so Session pins ctx
// before CSRF reads it.
func (i *Identity) SessionMiddleware() func(http.Handler) http.Handler { return i.sessionMW }

// CSRFMiddleware returns the CSRF middleware. Always inner to Session.
func (i *Identity) CSRFMiddleware() func(http.Handler) http.Handler { return i.csrfMW }

// OIDCEnabled reports whether a usable OIDC configuration was present after boot seeding (env-seeded or already stored). cmd/main uses
// it to log a single info-level line at startup summarising the auth modes the deployment honours. It reflects boot-time state; an
// admin who configures OIDC via the UI afterward enables SSO at runtime without flipping this flag (the login routes are always
// mounted when the handler is built).
func (i *Identity) OIDCEnabled() bool { return i.oidcConfiguredAtBoot }

// RegisterPublicRoutes wires DELETE /api/session (logout) plus the pre-auth OIDC + break-glass routes (when configured).
// Sessions are minted by the OIDC callback or the break-glass FinishLogin / FinishSetup endpoints; there is no
// password-based login surface.
func (i *Identity) RegisterPublicRoutes(mux *http.ServeMux) {
	i.loginHandler.RegisterPublicRoutes(mux)
	if i.oidcHandler != nil {
		i.oidcHandler.RegisterPublicRoutes(mux)
	}
	if i.breakglassHandler != nil {
		i.breakglassHandler.RegisterPublicRoutes(mux)
	}
}

// BreakglassService exposes the break-glass service so cmd/main can call IssueSetupToken on first boot. Returns nil when the deployment
// opted out of the break-glass surface.
func (i *Identity) BreakglassService() *breakglass.Service {
	return i.breakglassService
}

// BreakglassUIMiddleware returns the IP allowlist gate cmd/main wraps
// around the React UI's break-glass subroutes (/ui/admin/break-glass
// and /ui/admin/break-glass/setup). Without this gate, an off-allowlist
// caller could load the React shell at those paths even though the
// API endpoints behind them 404, defeating the path-concealment
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

// RegisterAuthedRoutes wires GET /api/session (who-am-i), GET /api/audit-events (operator-action history), the SSO settings API
// (/api/settings/sso), and the break-glass reauth POST endpoints. Caller wraps in SessionMiddleware + CSRFMiddleware before mounting.
func (i *Identity) RegisterAuthedRoutes(mux *http.ServeMux) {
	i.loginHandler.RegisterAuthedRoutes(mux)
	i.auditHandler.RegisterAuthedRoutes(mux)
	if i.ssoAdminHandler != nil {
		i.ssoAdminHandler.RegisterAuthedRoutes(mux)
	}
	if i.breakglassHandler != nil {
		i.breakglassHandler.RegisterAuthedRoutes(mux)
	}
}

// AuditRecorder returns the cross-context-callable AuditRecorder. Other contexts (response, rules, endpoint) take this as a
// constructor dependency and call Record() at the point an operator action commits; see api.AuditRecorder for the interface contract.
func (i *Identity) AuditRecorder() api.AuditRecorder { return i.auditStore }

// AuthZ returns the chokepoint engine. Subsequent per-context changes wire this into every privileged handler in detection / rules /
// response / endpoint; today the only consumer is the per-context tests that exercise the public api.AuthZ surface.
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
