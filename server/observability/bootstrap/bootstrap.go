package bootstrap

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/internal/observability/tracing"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/observability/internal/tracingadmin"
	"github.com/fleetdm/edr/server/observability/internal/tracingconfig"
	observabilitymigrations "github.com/fleetdm/edr/server/observability/migrations"
)

// Deps bundles what New needs. cmd/main owns the *sqlx.DB handle and shares it across every context's bootstrap.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger

	// AuthZ is the authorization chokepoint the trace-settings admin endpoints gate on (api.ActionTracingManage). Required.
	// cmd/main wires identityCtx.AuthZ().
	AuthZ identityapi.AuthZ
	// Audit is the operator-action recorder for sampler-settings updates. Required: these runtime knobs materially change incident
	// visibility, so a wiring mistake must fail fast rather than silently expose the endpoints with no audit trail. cmd/main wires
	// identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder
}

// Observability is the handle cmd/main holds for the observability bounded context.
type Observability struct {
	store   *tracingconfig.Store
	handler *tracingadmin.Handler
	db      *sqlx.DB
	logger  *slog.Logger
}

// New wires the observability context. Does NOT apply the schema (call ApplySchema for that).
func New(deps Deps) (*Observability, error) {
	if deps.DB == nil {
		return nil, errors.New("observability bootstrap: DB is required")
	}
	if deps.AuthZ == nil {
		return nil, errors.New("observability bootstrap: AuthZ is required")
	}
	if deps.Audit == nil {
		return nil, errors.New("observability bootstrap: Audit is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	store := tracingconfig.New(deps.DB)
	return &Observability{
		store:   store,
		handler: tracingadmin.NewHandler(store, deps.AuthZ, deps.Audit, logger),
		db:      deps.DB,
		logger:  logger,
	}, nil
}

// ApplySchema applies observability's goose migration corpus. Idempotent (goose skips already-applied versions). No cross-context FKs;
// ordering with other contexts' ApplySchema is not load-bearing.
func (o *Observability) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, o.db)
}

// ApplySchema is the package-level form: applies observability's goose migration corpus against the given DB without requiring a fully
// constructed *Observability. Used by server/testdb/full so tests can apply every context's schema. Idempotent.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("observability ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, observabilitymigrations.FS, runner.Options{
		Context:   "observability",
		TableName: "observability_goose_db_version",
	})
}

// RegisterAuthedRoutes wires the operator-facing trace-settings routes:
//
//	GET   /api/settings/tracing
//	PATCH /api/settings/tracing
//
// Caller wraps in identity.SessionMiddleware + identity.CSRFMiddleware before mounting.
func (o *Observability) RegisterAuthedRoutes(mux httpserver.Router) {
	o.handler.RegisterAuthedRoutes(mux)
}

// TraceSamplerSettingsReader returns the read accessor the per-replica OTel sampler poller depends on (issue #374). cmd/main passes it
// to tracing.StartSettingsPoller; the poller depends on the tracing.SettingsReader interface and this returns the concrete store that
// satisfies it.
func (o *Observability) TraceSamplerSettingsReader() tracing.SettingsReader { return o.store }
