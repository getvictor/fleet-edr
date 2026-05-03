package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/enroll"
	"github.com/fleetdm/edr/server/endpoint/internal/middleware"
	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
	"github.com/fleetdm/edr/server/endpoint/internal/operator"
	"github.com/fleetdm/edr/server/endpoint/internal/service"
)

// CommandInserter is the closure cmd/main supplies so the post-enroll
// fan-out can queue the initial set_blocklist command without
// endpoint importing response/api directly. Method-value-shaped to
// match response.Service.Insert exactly: cmd/main passes
// `responseCtx.Service().Insert` here as a one-liner.
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
	// fan-out. Satisfied today by rules.api.PolicyService.
	PolicyProvider api.PolicyProvider
	// CommandInserter inserts the initial set_blocklist command for
	// new agents. Must be nil-or-non-nil paired with PolicyProvider.
	// Satisfied today by response.api.Service.Insert via a method
	// value; the closure pattern matches what rules uses and avoids
	// endpoint importing response/api.
	CommandInserter CommandInserter
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
	// PolicyProvider + CommandInserter are paired. Letting the mismatch
	// fall through to service.New's panic would crash startup with no
	// recoverable error; surface it as a config error instead so the
	// caller's err-handling sees it.
	if (deps.PolicyProvider == nil) != (deps.CommandInserter == nil) {
		return nil, errors.New("endpoint bootstrap: PolicyProvider and CommandInserter must be set together (or both nil)")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	store := mysql.NewStore(deps.DB)
	svc := service.New(store, deps.EnrollSecret, deps.PolicyProvider, deps.CommandInserter, logger)

	return &Endpoint{
		svc: svc,
		enrollH: enroll.New(svc, enroll.Options{
			RatePerMinute: deps.EnrollRatePerMinute,
			Logger:        logger,
		}),
		operatorH:   operator.New(svc, logger),
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
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("endpoint ApplySchema: db must not be nil")
	}
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("endpoint schema create: %w", err)
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
