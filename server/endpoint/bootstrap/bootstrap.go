package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/enroll"
	"github.com/fleetdm/edr/server/endpoint/internal/middleware"
	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
	"github.com/fleetdm/edr/server/endpoint/internal/operator"
	"github.com/fleetdm/edr/server/endpoint/internal/revocation"
	"github.com/fleetdm/edr/server/endpoint/internal/service"
	"github.com/fleetdm/edr/server/endpoint/internal/signedtoken"
	"github.com/fleetdm/edr/server/endpoint/internal/token"
	endpointmigrations "github.com/fleetdm/edr/server/endpoint/migrations"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
)

// hostTokenKeyID labels the active host-token signing key; it is carried in every token's claims and checked on verify. Bump when
// rotating the signing key (and add an overlap verifier for the old id).
const hostTokenKeyID = "v1"

// DefaultRevocationRefreshInterval is how often each replica reloads the revocation snapshot from the database. It bounds the
// worst-case staleness of a revocation / credential-cycle across replicas. 5s keeps a kill switch effectively immediate without
// hammering the DB (one small query per replica per interval).
const DefaultRevocationRefreshInterval = 5 * time.Second

// CommandInserter is the closure cmd/main supplies so endpoint can queue commands (today: rotate_token) without importing response/api
// directly. Method-value-shaped to match response.Service.Insert exactly: cmd/main passes `responseCtx.Service().Insert` here as a
// one-liner.
type CommandInserter = service.CommandInserter

// Deps bundles what New needs to wire the endpoint context. cmd/main owns the *sqlx.DB handle and shares it across every context's
// bootstrap.
type Deps struct {
	DB                  *sqlx.DB
	Logger              *slog.Logger
	EnrollSecret        string
	EnrollRatePerMinute int
	// HostTokenPepper is the server-held HMAC key the enrollment store uses to hash the legacy host_token columns. Required, at least 32
	// bytes. cmd/main derives it from the deployment root secret (EDR_SECRET_KEY) via internal/keyring. Retained for the enrollment row's
	// columns; agent auth no longer verifies against it (see HostTokenSigningKey).
	HostTokenPepper []byte
	// HostTokenSigningKey is the server-held HMAC key that signs + verifies self-validating host tokens. Required, at least 32 bytes.
	// cmd/main derives it from the deployment root secret via internal/keyring under a distinct label, so it is independent of the
	// pepper. Changing the root (or the label) invalidates every outstanding token: a fleet-wide re-enroll.
	HostTokenSigningKey []byte

	// Audit is the operator-action recorder. Optional: nil disables audit emission for enrollment.revoke + enrollment.rotate_token.
	// cmd/main wires identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder

	// AuthZ is the authorization chokepoint every privileged operator
	// route gates on. Required. cmd/main wires identityCtx.AuthZ().
	AuthZ identityapi.AuthZ

	// HostTokenLifetime is the TTL of a minted signed host token: how long it is valid before the agent must refresh it. Zero -> service
	// default (60m). cmd/main reads EDR_HOST_TOKEN_LIFETIME.
	HostTokenLifetime time.Duration
}

// Endpoint is the handle cmd/main holds for the endpoint bounded context. It exposes the Service for cross-context callers (today:
// metrics' EnrolledHosts gauge), the host-token middleware factory, the route-registration methods, and ApplySchema.
type Endpoint struct {
	svc         api.Service
	enrollH     *enroll.Handler
	operatorH   *operator.Handler
	tokenH      *token.Handler
	hostTokenMW func(http.Handler) http.Handler
	snapshot    *revocation.Snapshot
	db          *sqlx.DB
	logger      *slog.Logger
}

// New wires the endpoint context. Does NOT apply the schema (call ApplySchema for that). Returns an error if Deps is missing required
// fields.
func New(deps Deps) (*Endpoint, error) {
	if deps.DB == nil {
		return nil, errors.New("endpoint bootstrap: DB is required")
	}
	if deps.EnrollSecret == "" {
		return nil, errors.New("endpoint bootstrap: EnrollSecret is required")
	}
	if len(deps.HostTokenPepper) < 32 {
		return nil, errors.New("endpoint bootstrap: HostTokenPepper is required (at least 32 bytes)")
	}
	if len(deps.HostTokenSigningKey) < 32 {
		return nil, errors.New("endpoint bootstrap: HostTokenSigningKey is required (at least 32 bytes)")
	}
	if deps.AuthZ == nil {
		return nil, errors.New("endpoint bootstrap: AuthZ is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	signer, err := signedtoken.New(deps.HostTokenSigningKey, hostTokenKeyID)
	if err != nil {
		return nil, fmt.Errorf("endpoint bootstrap: host token signer: %w", err)
	}
	store := mysql.NewStore(deps.DB, deps.HostTokenPepper)
	snapshot := revocation.NewSnapshot(store, logger)
	svc := service.New(service.Options{
		Store:       store,
		Secret:      deps.EnrollSecret,
		Signer:      signer,
		Revocations: snapshot,
		Audit:       deps.Audit,
		TokenTTL:    deps.HostTokenLifetime,
		Logger:      logger,
	})

	opH := operator.New(svc, deps.AuthZ, logger)
	opH.SetAudit(deps.Audit)
	return &Endpoint{
		svc: svc,
		enrollH: enroll.New(svc, enroll.Options{
			RatePerMinute: deps.EnrollRatePerMinute,
			Logger:        logger,
		}),
		operatorH:   opH,
		tokenH:      token.New(svc, logger),
		hostTokenMW: middleware.HostToken(svc, logger),
		snapshot:    snapshot,
		db:          deps.DB,
		logger:      logger,
	}, nil
}

// ApplySchema applies endpoint's goose migration corpus. Idempotent (goose skips already-applied versions). No cross-context FKs;
// ordering with other contexts' ApplySchema is not load-bearing.
func (e *Endpoint) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, e.db)
}

// ApplySchema is the package-level form: applies endpoint's goose migration corpus against the given DB without requiring a fully
// constructed *Endpoint. Used by server/testdb so tests can apply every context's schema without faking out each bootstrap's
// service dependencies. Idempotent (goose skips already-applied versions), so a second call on an already-migrated DB is a no-op.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("endpoint ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, endpointmigrations.FS, runner.Options{
		Context:   "endpoint",
		TableName: "endpoint_goose_db_version",
	})
}

// Service exposes the public api.Service for cross-context callers. Today: cmd/main's serverGaugeSource calls Service().CountActive
// for the EnrolledHosts metrics gauge.
func (e *Endpoint) Service() api.Service { return e.svc }

// HostTokenMiddleware returns the per-request middleware that gates agent endpoints. cmd/main chains this on POST /api/events,
// GET /api/commands, PUT /api/commands/{id}, and POST /api/token/refresh.
func (e *Endpoint) HostTokenMiddleware() func(http.Handler) http.Handler { return e.hostTokenMW }

// TokenRefreshHandler returns the POST /api/token/refresh handler. cmd/main mounts it inside the host-token-protected mux so it shares
// the same authentication as the other agent routes.
func (e *Endpoint) TokenRefreshHandler() http.Handler { return e.tokenH }

// RevocationSnapshot returns the per-replica revocation snapshot so cmd/main can trigger an initial synchronous load before serving and
// run the background refresh loop. Per ADR-0010 it is a perf cache, safe to lose.
func (e *Endpoint) RevocationSnapshot() *revocation.Snapshot { return e.snapshot }

// RegisterPublicRoutes wires POST /api/enroll. Public because the agent
// has no token yet; the handler does its own per-IP rate limit + audit.
func (e *Endpoint) RegisterPublicRoutes(mux *http.ServeMux) {
	e.enrollH.RegisterRoutes(mux)
}

// RegisterAuthedRoutes wires the operator-facing routes: GET /api/enrollments and POST /api/enrollments/{host_id}/revoke. Caller wraps
// in identity Session + CSRF middleware before mounting.
func (e *Endpoint) RegisterAuthedRoutes(mux *http.ServeMux) {
	e.operatorH.RegisterRoutes(mux)
}
