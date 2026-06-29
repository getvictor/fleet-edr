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

	"github.com/fleetdm/edr/server/httpserver"
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
	"github.com/fleetdm/edr/server/identity/internal/saadmin"
	"github.com/fleetdm/edr/server/identity/internal/satoken"
	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/identity/internal/service"
	"github.com/fleetdm/edr/server/identity/internal/serviceaccounts"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/ssoadmin"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/identity/internal/useradmin"
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

	// OIDC carries the live OIDC handler knobs (state-cookie TTL, optional test HTTP client). The provider connection config lives in
	// the durable oidc_config store, not here; the handler + routes are always built when the signing/secret keys are supplied, and the
	// login flow resolves the provider from the store per request (issue #375).
	OIDC OIDCDeps
	// SessionSigningKey is the HMAC key the OIDC state cookie reuses (per spec). Required when OIDC.Issuer is set; ignored otherwise.
	// 32+ bytes recommended. The break-glass challenge cookie reuses the same key.
	SessionSigningKey []byte
	// OIDCSecretKey seals the stored OIDC client secret at rest (keyring label edr/oidc/client-secret/v1). Required to build the
	// runtime OIDC config store; when empty (minimal test wiring) the OIDC handler is not constructed.
	OIDCSecretKey []byte
	// ServiceAccountTokenSigningKey signs service-account access tokens (keyring label edr/service-account-token/sign/v1). Required to
	// build the service-account surface; when empty (minimal test wiring) the service-account handlers are not constructed.
	ServiceAccountTokenSigningKey []byte

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

// OIDCDeps carries the live, deployment-level knobs the OIDC handler needs at construction time. The provider connection config
// (issuer, client id, secret, scopes, JIT toggle, default role) is NOT here: it lives in the durable oidc_config store and is read
// per-login (issue #375), so these are only the handler's runtime parameters. Lifted out of Deps so OIDC additions don't widen the
// parent struct.
type OIDCDeps struct {
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
	// ssoStore is the durable OIDC config store (nil when the OIDC handler was not built); it is the runtime source of truth the login
	// path resolves the provider from and the signal OIDCEnabled reports on.
	ssoStore        *ssoconfig.Store
	appConfigStore  *appconfig.Store
	ssoAdminHandler *ssoadmin.Handler // nil when the OIDC handler was not built (no signing/secret key)
	// Service-account surface (issue #376). All nil when no SA signing key was provided (minimal test wiring). saSnapshot is a
	// per-replica revocation cache; apiAuthMW is the combined bearer-or-session+CSRF middleware for the operator API mux.
	saAdminHandler *saadmin.Handler
	saTokenHandler *saadmin.TokenHandler
	saSnapshot     *serviceaccounts.Snapshot
	apiAuthMW      func(http.Handler) http.Handler
	// userAdminHandler serves the admin user-management surface (issue #135). Always built (it needs only the users + rbac stores).
	userAdminHandler *useradmin.Handler
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
	// A service-account store for the Service's principal-label resolver (svc_<id> -> name). It is a plain DB reader and does not depend
	// on the SA token-signing key, so it is wired unconditionally even when the SA token surface is disabled; the token surface builds
	// its own store.
	svc := service.New(usersStore, sessionsStore, rbacStore, serviceaccounts.New(deps.DB), logger)
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
	// OIDC config store exists (i.e. keys were supplied), else nil and the surface is not mounted.
	ssoAdminHandler := buildSSOAdminHandler(ssoAdminHandlerDeps{
		deps:      deps,
		logger:    logger,
		ssoStore:  ssoStore,
		appConfig: appConfigStore,
		authz:     authzEngine,
		audit:     auditStore,
	})

	// Service-account surface (issue #376, ADR-0013). Built only when a signing key was provided (zero-valued in minimal test wiring).
	sessionMW := middleware.Session(svc, logger)
	csrfMW := middleware.CSRF(logger)
	saSurface, err := buildServiceAccountSurface(deps, authzEngine, auditStore, sessionMW, csrfMW, logger)
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
			Permissions:  authzEngine,
		}),
		oidcHandler:       oidcHandler,
		breakglassHandler: bgHandler,
		breakglassService: bgService,
		auditStore:        auditStore,
		auditHandler:      audit.NewHandler(auditStore, authzEngine, logger),
		auditAsync:        auditAsync,
		sessionMW:         sessionMW,
		csrfMW:            csrfMW,
		db:                deps.DB,
		logger:            logger,
		cleanupEvery:      cleanupEvery,
		ssoStore:          ssoStore,
		appConfigStore:    appConfigStore,
		ssoAdminHandler:   ssoAdminHandler,
		saAdminHandler:    saSurface.adminHandler,
		saTokenHandler:    saSurface.tokenHandler,
		saSnapshot:        saSurface.snapshot,
		apiAuthMW:         saSurface.apiAuthMW,
		userAdminHandler:  useradmin.NewHandler(usersStore, rbacStore, authzEngine, auditStore, logger),
	}, nil
}

// ssoAdminHandlerDeps bundles the per-call inputs to buildSSOAdminHandler. Same shape pattern as oidcHandlerDeps so future field
// additions don't widen the function signature.
type ssoAdminHandlerDeps struct {
	deps      Deps
	logger    *slog.Logger
	ssoStore  *ssoconfig.Store
	appConfig *appconfig.Store
	authz     *authz.Engine
	audit     *audit.Store
}

// buildSSOAdminHandler builds the SSO admin API (read/update/test-connection). It returns nil when no OIDC config store exists (no
// keys supplied), in which case the surface is simply not mounted. apply writes oidc_config and app_config in ONE transaction so a
// partial failure can't pair a new issuer with a stale derived redirect; app_config carries the optimistic-concurrency version check.
func buildSSOAdminHandler(in ssoAdminHandlerDeps) *ssoadmin.Handler {
	if in.ssoStore == nil {
		return nil
	}
	oidcHTTPClient := in.deps.OIDC.HTTPClient
	apply := func(ctx context.Context, oidcIn ssoconfig.UpsertInput, appCfg appconfig.AppConfig, expectedAppVersion int64, updatedBy string) error {
		tx, err := in.deps.DB.BeginTxx(ctx, nil)
		if err != nil {
			return fmt.Errorf("identity bootstrap: begin sso update tx: %w", err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		if err := in.ssoStore.UpsertTx(ctx, tx, oidcIn); err != nil {
			return err
		}
		if err := in.appConfig.PutTx(ctx, tx, appCfg, expectedAppVersion, updatedBy); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("identity bootstrap: commit sso update tx: %w", err)
		}
		committed = true
		return nil
	}
	return ssoadmin.NewHandler(in.ssoStore, in.appConfig, apply, in.authz, in.audit,
		func(ctx context.Context, issuer string) error { return oidc.Probe(ctx, issuer, oidcHTTPClient) }, in.logger)
}

// serviceAccountSurface bundles the optional service-account handlers plus the API-auth middleware. All fields are nil/zero in
// minimal test wiring (no signing key supplied).
type serviceAccountSurface struct {
	adminHandler *saadmin.Handler
	tokenHandler *saadmin.TokenHandler
	snapshot     *serviceaccounts.Snapshot
	apiAuthMW    func(http.Handler) http.Handler
}

// buildServiceAccountSurface builds the service-account surface (issue #376, ADR-0013) when a token signing key was provided,
// returning a zero surface otherwise. The snapshot is a per-replica revocation cache (ADR-0010 safe-to-lose); cmd/main starts its
// refresh loop. apiAuthMW chains the SA authenticator ahead of the session + CSRF middleware.
func buildServiceAccountSurface(deps Deps, authzEngine *authz.Engine, auditStore *audit.Store,
	sessionMW, csrfMW func(http.Handler) http.Handler, logger *slog.Logger) (serviceAccountSurface, error) {
	if len(deps.ServiceAccountTokenSigningKey) == 0 {
		return serviceAccountSurface{}, nil
	}
	saStore := serviceaccounts.New(deps.DB)
	saSigner, err := satoken.New(deps.ServiceAccountTokenSigningKey, serviceAccountTokenKeyID, serviceAccountTokenAudience)
	if err != nil {
		return serviceAccountSurface{}, fmt.Errorf("identity bootstrap: service-account token signer: %w", err)
	}
	snapshot := serviceaccounts.NewSnapshot(saStore, logger)
	authenticator := serviceaccounts.NewAuthenticator(saSigner, snapshot)
	return serviceAccountSurface{
		adminHandler: saadmin.NewHandler(saStore, authzEngine, auditStore, logger),
		tokenHandler: saadmin.NewTokenHandler(saStore, saSigner, auditStore, logger),
		snapshot:     snapshot,
		apiAuthMW:    middleware.APIAuth(authenticator, sessionMW, csrfMW, logger),
	}, nil
}

const (
	// serviceAccountTokenKeyID labels the current SA signing key inside the token, so a future key rotation can verify old + new
	// during an overlap window. serviceAccountTokenAudience binds tokens to the API; cross-deployment forgery is additionally blocked
	// by the per-deployment signing key.
	serviceAccountTokenKeyID    = "v1"
	serviceAccountTokenAudience = "edr-api"
)

// DefaultServiceAccountRevocationRefreshInterval re-exports the per-replica service-account revocation snapshot refresh cadence so
// cmd/main (which cannot import the identity-internal package) can drive the background refresh loop.
const DefaultServiceAccountRevocationRefreshInterval = serviceaccounts.DefaultRevocationRefreshInterval

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

// buildBreakglass constructs the break-glass Service + Handler. Break-glass is the bootstrap login path the first admin uses before any
// SSO config exists (SSO is configured at runtime through the UI after a break-glass login), so it is always available: when no
// EDR_BREAKGLASS_* is set it defaults to a localhost configuration (the dev shape; production sets the externally reachable RP id +
// origins). Returns an error when the operator partially configured the surface.
func buildBreakglass(in breakglassDeps) (*breakglass.Service, *breakglass.Handler, error) {
	bg := in.deps.Breakglass
	rpID := bg.RPID
	rpOrigins := bg.RPOrigins
	if rpID == "" && len(rpOrigins) == 0 {
		// Nothing configured: default to localhost so first boot has a working recovery surface without a long env var prelude. The
		// origins are https:// to match the server's mandatory-TLS posture (issue #140); the browser hits https://localhost:8088, so the
		// WebAuthn origin check would reject http:// here. Production sets EDR_BREAKGLASS_RP_ID + EDR_BREAKGLASS_RP_ORIGINS to the
		// externally reachable host.
		rpID = "localhost"
		rpOrigins = []string{"https://localhost:8088", "https://127.0.0.1:8088"}
	}
	// Reject partial config: an operator who set RP_ORIGINS WITHOUT RP_ID intended to configure break-glass; silently defaulting to the
	// localhost RP id would brick recovery against the wrong relying party.
	if rpID == "" && len(rpOrigins) > 0 {
		return nil, nil, errors.New(
			"identity bootstrap: EDR_BREAKGLASS_RP_ORIGINS set without EDR_BREAKGLASS_RP_ID")
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
// The returned *ssoconfig.Store is retained by New as the runtime source of truth the resolver reads and the signal OIDCEnabled reports
// on.
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
		redirectURL := ssoconfig.RedirectURLFor(appCfg.ExternalURL)
		if redirectURL == "" {
			// OIDC rows exist but the deployment external URL is unset, so the redirect cannot be derived. Surface this as "not
			// configured" (a directed login response) rather than letting an empty redirect fail opaquely in client construction.
			return oidc.ProviderConfig{}, oidc.ErrNotConfigured
		}
		return oidc.ProviderConfig{
			Issuer:       c.Issuer,
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  redirectURL,
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
	return ApplySchema(ctx, i.db)
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

// OIDCSeedInput is the connection configuration SeedOIDCConfig persists, mirroring the fields an admin enters in the Single sign-on
// settings UI. The redirect URI is not part of it: it is derived at read time from ExternalURL as ExternalURL + /api/auth/callback.
type OIDCSeedInput struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	JITEnabled   bool
	DefaultRole  string
	ExternalURL  string
	// Force overwrites an existing stored config instead of treating its presence as a no-op. It exists only for non-interactive test
	// harnesses (the e2e coverage run re-points the JIT toggle between phases); the demo and production seed paths leave it false so a
	// later UI edit is never clobbered.
	Force bool
}

// SeedOIDCConfig writes a deployment OIDC configuration (and the deployment external URL) directly to the durable identity stores,
// sealing the client secret with oidcSecretKey. That key is the AES-256 sealer key the runtime store uses, i.e. the same value the
// server passes as Deps.OIDCSecretKey (keyring.Derive(OIDCClientSecretLabel) of EDR_SECRET_KEY); the caller derives it the same way so
// the sealed secret decrypts at login. It exists for non-interactive bootstrapping, the demo and local-QA stacks, where no operator is
// present to use the Single sign-on settings UI; production deployments configure SSO through the UI/API. It is a no-op when a stored
// OIDC config already exists (unless OIDCSeedInput.Force), so it is safe to re-run and never clobbers a later UI edit, and it seeds the
// external URL only when the app_config document has none, for the same reason. The JIT default role is clamped to the analyst/auditor
// floor the SSO admin API enforces (a non-interactive caller cannot seed a privileged default role), and the two writes commit in one
// transaction. This is a bootstrap-only seam: like the pre-#512 env seed it writes as the system principal and does not pass through the
// authorization chokepoint (there is no operator/session at seed time); operator-initiated SSO changes go through the audited admin API.
func SeedOIDCConfig(ctx context.Context, db *sqlx.DB, oidcSecretKey []byte, in OIDCSeedInput) error {
	if db == nil {
		return errors.New("identity SeedOIDCConfig: db must not be nil")
	}
	if in.Issuer == "" {
		return errors.New("identity SeedOIDCConfig: issuer is required")
	}
	sealer, err := ssoconfig.NewSealer(oidcSecretKey)
	if err != nil {
		return fmt.Errorf("identity SeedOIDCConfig: build secret sealer: %w", err)
	}
	store := ssoconfig.New(db, sealer)
	// Skip only when a USABLE (decryptable) config already exists and we are not forcing. Gating on decryptability, not mere row
	// presence, avoids silently no-opping over a row whose secret cannot be decrypted (e.g. after an EDR_SECRET_KEY rotation), which would
	// leave SSO unusable while OIDCEnabled reports false; that surfaces as an error so the caller can rerun with Force to overwrite.
	if !in.Force {
		switch _, err := store.GetDecrypted(ctx); {
		case err == nil:
			return nil // a usable stored config governs; leave it untouched
		case !errors.Is(err, ssoconfig.ErrNotFound):
			return fmt.Errorf("identity SeedOIDCConfig: read OIDC config: %w", err)
		}
	}
	// Write oidc_config and the external URL in ONE transaction (same shape as the admin API's apply), so a partial failure can't leave a
	// stored OIDC config paired with a missing derived redirect; a rolled-back seed re-runs cleanly.
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("identity SeedOIDCConfig: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	secret := in.ClientSecret
	if err := store.UpsertTx(ctx, tx, ssoconfig.UpsertInput{
		Issuer:      in.Issuer,
		ClientID:    in.ClientID,
		NewSecret:   &secret,
		Scopes:      in.Scopes,
		JITEnabled:  in.JITEnabled,
		DefaultRole: clampJITRole(in.DefaultRole),
		UpdatedBy:   api.PrincipalSystemID,
	}); err != nil {
		return fmt.Errorf("identity SeedOIDCConfig: write OIDC config: %w", err)
	}
	if err := seedExternalURLTx(ctx, tx, db, in.ExternalURL); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("identity SeedOIDCConfig: commit tx: %w", err)
	}
	committed = true
	return nil
}

// clampJITRole normalizes a seeded JIT default role to the analyst/auditor floor the SSO admin API enforces. Anything outside that set
// (including the empty default) falls back to the lowest-privilege JIT role, so a non-interactive seed (demo/CI) cannot set
// default_role=admin and have the OIDC provisioner auto-bind first-time SSO users to a privileged role. Mirrors ssoadmin + the
// pre-#512 env-seed behaviour.
func clampJITRole(role string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	if r == "analyst" || r == "auditor" {
		return r
	}
	return oidc.DefaultJITRole
}

// seedExternalURLTx seeds the deployment external URL into the app_config document within tx, but only when the document has none, so a
// later UI edit is never clobbered. No-op when externalURL is empty. The version read is the optimistic-concurrency stamp PutTx checks.
func seedExternalURLTx(ctx context.Context, tx *sqlx.Tx, db *sqlx.DB, externalURL string) error {
	if externalURL == "" {
		return nil
	}
	appCfg := appconfig.New(db)
	cur, version, err := appCfg.Get(ctx)
	if err != nil {
		return fmt.Errorf("identity SeedOIDCConfig: read app config: %w", err)
	}
	if cur.ExternalURL != "" {
		return nil // operator already set it; don't clobber
	}
	cur.ExternalURL = externalURL
	if err := appCfg.PutTx(ctx, tx, cur, version, api.PrincipalSystemID); err != nil {
		return fmt.Errorf("identity SeedOIDCConfig: seed external URL: %w", err)
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

// APIAuthMiddleware returns the operator-API auth front door: a bearer service-account token is verified statelessly and pinned as an
// actor (CSRF-exempt), and any other request takes the cookie session + CSRF path (ADR-0013). Returns nil when the service-account
// surface was not built (no signing key); cmd/main falls back to SessionMiddleware(CSRFMiddleware(...)) in that case.
func (i *Identity) APIAuthMiddleware() func(http.Handler) http.Handler { return i.apiAuthMW }

// ServiceAccountSnapshot returns the per-replica service-account revocation snapshot so cmd/main can load it once synchronously before
// serving and run the background refresh loop. Nil when the service-account surface was not built. Per ADR-0010 it is a perf cache,
// safe to lose.
func (i *Identity) ServiceAccountSnapshot() *serviceaccounts.Snapshot { return i.saSnapshot }

// OIDCEnabled reports whether a usable OIDC configuration exists in the durable store. It is the fail-closed signal derived from the
// oidc_config store (issue #512 removed the env-var boot gate in favour of always-boot): it returns false when the OIDC handler was not
// built (no signing/secret key) or no configuration has been saved yet, and true once an admin saves one via the UI/API, with no
// restart. The login routes are always mounted when the handler is built, so this is a status signal, not a routing gate.
func (i *Identity) OIDCEnabled(ctx context.Context) bool {
	if i.ssoStore == nil {
		return false
	}
	// GetDecrypted, not Get: a row whose client secret cannot be decrypted (wrong/rotated sealer key) is not a usable config, so the
	// fail-closed signal must reflect decryptability, not mere row presence.
	_, err := i.ssoStore.GetDecrypted(ctx)
	return err == nil
}

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
	if i.saTokenHandler != nil {
		// The client-credentials token endpoint authenticates by the presented credential, not a session or host token, so it mounts
		// here (no session/CSRF wrapper) rather than on the authed mux.
		i.saTokenHandler.RegisterPublicRoutes(mux)
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
func (i *Identity) RegisterAuthedRoutes(mux httpserver.Router) {
	i.loginHandler.RegisterAuthedRoutes(mux)
	i.auditHandler.RegisterAuthedRoutes(mux)
	if i.ssoAdminHandler != nil {
		i.ssoAdminHandler.RegisterAuthedRoutes(mux)
	}
	if i.saAdminHandler != nil {
		i.saAdminHandler.RegisterAuthedRoutes(mux)
	}
	if i.userAdminHandler != nil {
		i.userAdminHandler.RegisterAuthedRoutes(mux)
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
