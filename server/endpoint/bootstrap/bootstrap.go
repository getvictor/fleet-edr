package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/enroll"
	"github.com/fleetdm/edr/server/endpoint/internal/middleware"
	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
	"github.com/fleetdm/edr/server/endpoint/internal/operator"
	"github.com/fleetdm/edr/server/endpoint/internal/service"
	endpointmigrations "github.com/fleetdm/edr/server/endpoint/migrations"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
)

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
	// HostTokenPepper is the server-held HMAC key the enrollment store uses to hash + verify host tokens. Required, at least 32 bytes.
	// cmd/main derives it from the deployment root secret (EDR_SECRET_KEY) via internal/keyring; changing the root invalidates every
	// existing host token (a breaking, operator-initiated fleet-wide re-enroll).
	HostTokenPepper []byte
	// CommandInserter inserts commands the endpoint context emits (today: only rotate_token). Optional: when nil, rotate_token commits the
	// new bearer to the DB but the agent will not receive a command: it re-enrolls once the grace window expires.
	CommandInserter CommandInserter

	// Audit is the operator-action recorder. Optional: nil disables audit emission for enrollment.revoke + enrollment.rotate_token.
	// cmd/main wires identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder

	// AuthZ is the authorization chokepoint every privileged operator
	// route gates on. Required. cmd/main wires identityCtx.AuthZ().
	AuthZ identityapi.AuthZ

	// HostTokenLifetime is how long a host bearer token may live before the verify path triggers an auto-rotation. Zero -> service default
	// (24h). cmd/main reads EDR_HOST_TOKEN_LIFETIME.
	HostTokenLifetime time.Duration
	// HostTokenGrace is the window during which the just-superseded token still verifies after rotation, so an in-flight agent poll
	// doesn't 401 mid-cycle. Zero -> service default (5m). cmd/main reads EDR_HOST_TOKEN_GRACE.
	HostTokenGrace time.Duration
}

// Endpoint is the handle cmd/main holds for the endpoint bounded context. It exposes the Service for cross-context callers (today:
// metrics' EnrolledHosts gauge), the host-token middleware factory, the route-registration methods, and ApplySchema.
type Endpoint struct {
	svc         api.Service
	enrollH     *enroll.Handler
	operatorH   *operator.Handler
	hostTokenMW func(http.Handler) http.Handler
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
	if deps.AuthZ == nil {
		return nil, errors.New("endpoint bootstrap: AuthZ is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	store := mysql.NewStore(deps.DB, deps.HostTokenPepper)
	svc := service.New(service.Options{
		Store:    store,
		Secret:   deps.EnrollSecret,
		Commands: deps.CommandInserter,
		Audit:    deps.Audit,
		Lifetime: deps.HostTokenLifetime,
		Grace:    deps.HostTokenGrace,
		Logger:   logger,
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
		hostTokenMW: middleware.HostToken(svc, logger),
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
// GET /api/commands, and PUT /api/commands/{id}.
func (e *Endpoint) HostTokenMiddleware() func(http.Handler) http.Handler { return e.hostTokenMW }

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
