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
	"github.com/fleetdm/edr/server/endpoint/internal/service"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// CommandInserter is the closure cmd/main supplies so the post-enroll
// fan-out can queue the initial set_blocklist command without
// endpoint importing response/api directly. Method-value-shaped to
// match response.Service.Insert exactly: phase-4 cmd/main passes
// `responseCtx.Service().Insert` here as a one-liner. Phase 5 may
// route through detection-context glue but the signature stays.
type CommandInserter = service.CommandInserter

// Deps bundles what New needs to wire the endpoint context. cmd/main
// owns the *sqlx.DB handle and shares it across every context's
// bootstrap.
type Deps struct {
	DB                  *sqlx.DB
	Logger              *slog.Logger
	EnrollSecret        string
	EnrollRatePerMinute int
	// PolicyProvider supplies the active blocklist for new agents at
	// enroll time. Nil-safe: when nil (or paired with a nil
	// CommandInserter), the enroll handler skips the post-enroll
	// fan-out. Satisfied today by rules.api.PolicyService (phase 3).
	PolicyProvider api.PolicyProvider
	// CommandInserter inserts the initial set_blocklist command for
	// new agents. Must be nil-or-non-nil paired with PolicyProvider.
	// Satisfied today by response.api.Service.Insert (phase 4) via a
	// method value. Was an interface (api.CommandInserter) in phases
	// 2+3; the closure pattern matches what rules has used since
	// phase 3 and removes one layer of interface boilerplate.
	CommandInserter CommandInserter

	// Audit is the operator-action recorder. Optional: nil disables
	// audit emission for enrollment.revoke + enrollment.token_rotated.
	// cmd/main wires identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder

	// HostTokenLifetime is how long a host bearer token may live before
	// the verify path triggers an auto-rotation. Zero -> service
	// default (24h). cmd/main reads EDR_HOST_TOKEN_LIFETIME.
	HostTokenLifetime time.Duration
	// HostTokenGrace is the window during which the just-superseded
	// token still verifies after rotation, so an in-flight agent poll
	// doesn't 401 mid-cycle. Zero -> service default (5m). cmd/main
	// reads EDR_HOST_TOKEN_GRACE.
	HostTokenGrace time.Duration
}

// Endpoint is the handle cmd/main holds for the endpoint bounded
// context. It exposes the Service for cross-context callers (today:
// metrics' EnrolledHosts gauge), the host-token middleware factory,
// the route-registration methods, and ApplySchema.
type Endpoint struct {
	svc         api.Service
	enrollH     *enroll.Handler
	operatorH   *operator.Handler
	hostTokenMW func(http.Handler) http.Handler
	db          *sqlx.DB
	logger      *slog.Logger
}

// New wires the endpoint context. Does NOT apply the schema (call
// ApplySchema for that). Returns an error if Deps is missing required
// fields.
func New(deps Deps) (*Endpoint, error) {
	if deps.DB == nil {
		return nil, errors.New("endpoint bootstrap: DB is required")
	}
	if deps.EnrollSecret == "" {
		return nil, errors.New("endpoint bootstrap: EnrollSecret is required")
	}
	// Policy without Commands is a config error (policy fan-out has nowhere
	// to send commands); Commands without Policy is allowed since rotation
	// uses Commands without consulting Policy. Surface this here as a
	// recoverable error rather than letting it fall through to service.New's
	// panic at boot.
	if deps.PolicyProvider != nil && deps.CommandInserter == nil {
		return nil, errors.New("endpoint bootstrap: PolicyProvider set but CommandInserter is nil; policy fan-out has nowhere to go")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	store := mysql.NewStore(deps.DB)
	svc := service.New(service.Options{
		Store:    store,
		Secret:   deps.EnrollSecret,
		Policy:   deps.PolicyProvider,
		Commands: deps.CommandInserter,
		Audit:    deps.Audit,
		Lifetime: deps.HostTokenLifetime,
		Grace:    deps.HostTokenGrace,
		Logger:   logger,
	})

	opH := operator.New(svc, logger)
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

// ApplySchema runs the DDL statements endpoint owns. Idempotent
// (CREATE TABLE IF NOT EXISTS). No cross-context FKs; ordering with
// other contexts' ApplySchema is not load-bearing.
func (e *Endpoint) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, e.db)
}

// ApplySchema is the package-level form: applies endpoint's DDL
// against the given DB without requiring a fully constructed
// *Endpoint. Used by server/testdb so tests can apply every context's
// schema without faking out each bootstrap's service dependencies.
//
// Two passes: schemaStatements first (CREATE TABLE IF NOT EXISTS),
// then schemaMigrations (idempotent ALTERs for upgrade paths).
// Migration errors that signal "already applied" are swallowed so
// re-running on a populated DB is a no-op.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("endpoint ApplySchema: db must not be nil")
	}
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("endpoint schema create: %w", err)
		}
	}
	for _, stmt := range schemaMigrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil && !isAlreadyAppliedMigration(err) {
			return fmt.Errorf("endpoint schema migration: %w", err)
		}
	}
	return nil
}

// Service exposes the public api.Service for cross-context callers.
// Today: cmd/main's serverGaugeSource calls Service().CountActive for
// the EnrolledHosts metrics gauge.
func (e *Endpoint) Service() api.Service { return e.svc }

// HostTokenMiddleware returns the per-request middleware that gates
// agent endpoints. cmd/main chains this on POST /api/events,
// GET /api/commands, and PUT /api/commands/{id}.
func (e *Endpoint) HostTokenMiddleware() func(http.Handler) http.Handler { return e.hostTokenMW }

// RegisterPublicRoutes wires POST /api/enroll. Public because the agent
// has no token yet; the handler does its own per-IP rate limit + audit.
func (e *Endpoint) RegisterPublicRoutes(mux *http.ServeMux) {
	e.enrollH.RegisterRoutes(mux)
}

// RegisterAuthedRoutes wires the operator-facing routes:
// GET /api/enrollments and POST /api/enrollments/{host_id}/revoke.
// Caller wraps in identity Session + CSRF middleware before mounting.
func (e *Endpoint) RegisterAuthedRoutes(mux *http.ServeMux) {
	e.operatorH.RegisterRoutes(mux)
}
