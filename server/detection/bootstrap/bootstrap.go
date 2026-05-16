package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/engine"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/intake"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/operator"
	"github.com/fleetdm/edr/server/detection/internal/pipeline"
	"github.com/fleetdm/edr/server/detection/internal/service"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// BuildInfo is injected by cmd/main and surfaced through the intake handler's livez/readyz payloads. Re-exported from
// detection/internal/intake so cmd/* don't have to reach into an internal package for the type.
type BuildInfo = intake.BuildInfo

// Mode controls which background goroutines + routes the bootstrap wires up. Two binaries consume this: fleet-edr-server (full mode)
// and fleet-edr-ingest (intake-only mode).
type Mode int

const (
	// ModeFull wires the full detection surface: ingest + operator
	// routes + processor + processttl + retention goroutines.
	ModeFull Mode = iota
	// ModeIntake skips processor / pipeline / operator surface; just
	// serves POST /api/events + health probes.
	ModeIntake
)

// UserExists is the closure cmd/main wires from identity.api.Service.UserExists. PUT /api/alerts/{id} calls it before persisting
// `updated_by` so that orphan user_ids cannot silently land on the row in the absence of a cross-context FK.
type UserExists = service.UserExists

// Deps bundles what New needs to wire the detection context.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger
	Mode   Mode

	// Build info passed through to the intake handler's livez/readyz
	// payloads. Optional.
	Build BuildInfo

	// Pipeline cadences (Full mode only). Zero values disable the
	// corresponding loop.
	ProcessInterval      time.Duration
	ProcessBatch         int
	StaleProcessTTL      time.Duration
	StaleProcessInterval time.Duration
	RetentionDays        int
	RetentionInterval    time.Duration

	// Cross-context inputs (Full mode only).
	UserExists UserExists
	Metrics    api.MetricsRecorder
	// Audit is the operator-action recorder. Optional: nil disables audit emission for alert-status changes (existing tests pass nil
	// without ceremony). cmd/main wires identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder
	// AuthZ is the authorization chokepoint every privileged operator route gates on. Required in ModeFull. cmd/main wires
	// identityCtx.AuthZ(); intake-only mode (ModeIntake) does not register the operator handler so AuthZ may be nil there.
	AuthZ identityapi.AuthZ
}

// Detection is the handle cmd/main holds.
type Detection struct {
	store     *mysql.Store
	engine    *engine.Engine
	intakeH   *intake.Handler
	operatorH *operator.Handler
	svc       *service.Service
	pipe      *pipeline.Runner
	db        *sqlx.DB
	mode      Mode
	logger    *slog.Logger
	metrics   api.MetricsRecorder
}

// New wires the detection context. Does NOT apply the schema (call
// ApplySchema for that) and does NOT run goroutines (call Run).
func New(deps Deps) (*Detection, error) {
	if deps.DB == nil {
		return nil, errors.New("detection bootstrap: DB is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	store, err := mysql.New(deps.DB)
	if err != nil {
		return nil, fmt.Errorf("detection bootstrap: %w", err)
	}

	intakeH := intake.New(store, logger, deps.Build)
	if deps.Metrics != nil {
		intakeH.SetMetrics(deps.Metrics)
	}

	det := &Detection{
		store:   store,
		intakeH: intakeH,
		db:      deps.DB,
		mode:    deps.Mode,
		logger:  logger,
		metrics: deps.Metrics,
	}

	if deps.Mode == ModeFull {
		det.engine = engine.New(store, logger)
		if deps.Metrics != nil {
			det.engine.SetMetrics(deps.Metrics)
		}
		query := graph.NewQuery(store)
		det.svc = service.New(store, query, intakeH, deps.UserExists, logger)
		if deps.AuthZ == nil {
			return nil, errors.New("detection bootstrap: AuthZ is required in ModeFull")
		}
		det.operatorH = operator.New(det.svc, deps.AuthZ, logger)
		det.operatorH.SetAudit(deps.Audit)

		processor := pipeline.NewProcessor(
			store,
			graph.NewBuilder(store, logger),
			det.engine,
			logger,
			deps.ProcessInterval,
			deps.ProcessBatch,
		)
		processTTL := pipeline.NewProcessTTL(store, pipeline.ProcessTTLOptions{
			MaxAge:   deps.StaleProcessTTL,
			Interval: deps.StaleProcessInterval,
			Logger:   logger,
		})
		retention := pipeline.NewRetention(deps.DB, pipeline.RetentionOptions{
			RetentionDays: deps.RetentionDays,
			Interval:      deps.RetentionInterval,
			Logger:        logger,
		})
		det.pipe = pipeline.NewRunner(pipeline.RunnerOptions{
			Processor:  processor,
			ProcessTTL: processTTL,
			Retention:  retention,
			DB:         deps.DB,
		})
	} else {
		// Intake-only: still expose a service with the intake handler
		// so RegisterIngestRoutes works.
		det.svc = service.New(store, nil, intakeH, deps.UserExists, logger)
	}

	return det, nil
}

// ApplySchema runs the CREATE TABLE statements detection owns. Idempotent.
func (d *Detection) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, d.db)
}

// ApplySchema is the package-level form: applies detection's DDL against the given DB without requiring a fully constructed
// *Detection. Used by server/testdb so tests can apply every context's schema without faking out each bootstrap's service
// dependencies.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("detection ApplySchema: db must not be nil")
	}
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("detection schema apply: %w", err)
		}
	}
	return applyAdditiveAlters(ctx, db)
}

// MySQL error numbers we treat as "already applied" for additive ALTER statements. Documented at
// https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html.
const (
	mysqlDuplicateColumn = 1060
	mysqlDuplicateKey    = 1061
)

// applyAdditiveAlters runs ALTER TABLE statements that add columns to tables already
// populated by an earlier deployment. The product hasn't shipped (no migration story
// yet -- issue #115), but dev DBs survive across branches and we want a `task dev:server`
// to work without a `task db:reset` after a schema bump on a feature branch.
//
// Statements run one-clause-at-a-time. Combining multiple ADD COLUMN / ADD INDEX clauses
// into a single ALTER fails atomically: if one clause was already applied by a previous
// pass and another is new, MySQL rejects the whole statement and isAlreadyAppliedError
// would skip past it, permanently stranding the un-applied clauses. Splitting into one
// statement per clause makes each idempotent in isolation (per review on PR #180).
//
// When the product ships, this whole function moves to a real migration runner (#115).
func applyAdditiveAlters(ctx context.Context, db *sqlx.DB) error {
	alters := []string{
		// issue #173: snapshot-aware TTL reconciliation. is_snapshot marks rows originated by the extension's baseline pass;
		// last_seen_ns is bumped by agent heartbeats. Index supports the heartbeat UPDATE's WHERE predicate.
		`ALTER TABLE processes ADD COLUMN is_snapshot BOOL NOT NULL DEFAULT FALSE`,
		`ALTER TABLE processes ADD COLUMN last_seen_ns BIGINT NULL`,
		`ALTER TABLE processes ADD INDEX idx_processes_snapshot_lastseen (is_snapshot, last_seen_ns)`,
	}
	for _, stmt := range alters {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			if isAlreadyAppliedError(err) {
				continue
			}
			return fmt.Errorf("detection additive alter: %w", err)
		}
	}
	return nil
}

// isAlreadyAppliedError matches MySQL errors that mean "this ALTER is a no-op because the change already exists." Uses errors.As
// against go-sql-driver's typed *mysql.MySQLError so a future message format change can't silently break the idempotency contract --
// substring-matching err.Error() was brittle (per review on PR #180). Mirrors the pattern in server/identity/internal/seed/admin.go.
func isAlreadyAppliedError(err error) bool {
	if err == nil {
		return false
	}
	var mErr *mysqldriver.MySQLError
	if errors.As(err, &mErr) {
		return mErr.Number == mysqlDuplicateColumn || mErr.Number == mysqlDuplicateKey
	}
	return false
}

// Service exposes the operator-facing api.Service. RecordHostSeen is
// the hot path response consumes via its Heartbeat closure.
func (d *Detection) Service() api.Service { return d.svc }

// SetMetrics wires the metrics recorder into the engine + intake + pipeline (processttl + retention) AFTER construction. Used by
// cmd/main to break the circular dependency between detectionCtx and metrics.New (the OfflineHosts gauge source needs detectionCtx;
// detectionCtx's engine + intake + pipeline need the recorder).
func (d *Detection) SetMetrics(m api.MetricsRecorder) {
	d.metrics = m
	if d.engine != nil {
		d.engine.SetMetrics(m)
	}
	if d.intakeH != nil {
		d.intakeH.SetMetrics(m)
	}
	if d.pipe != nil {
		d.pipe.SetMetrics(m)
	}
}

// Store exposes the persistence handle. Used by cmd/main for the
// retention DB-handle wiring (retention takes a *sqlx.DB directly).
func (d *Detection) Store() *mysql.Store { return d.store }

// LoadActive registers the active rule set with the engine. cmd/main
// calls this after rulesCtx is built. Skipped in ModeIntake (no engine).
func (d *Detection) LoadActive(rp interface{ ActiveRules() []rulesapi.Rule }) {
	if d.engine == nil {
		return
	}
	d.engine.LoadActive(rp)
}

// Run launches the processor + processttl + retention goroutines.
// Returns when ctx is cancelled. ModeIntake is a no-op.
func (d *Detection) Run(ctx context.Context) error {
	if d.pipe == nil {
		<-ctx.Done()
		return nil
	}
	return d.pipe.Run(ctx)
}

// RegisterIngestRoutes wires POST /api/events on the given mux.
// Caller wraps in endpoint.HostToken middleware before mounting.
func (d *Detection) RegisterIngestRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/events", d.intakeH.IngestHandler())
}

// RegisterHealthRoutes wires /livez, /readyz, /health (unauthenticated).
func (d *Detection) RegisterHealthRoutes(mux *http.ServeMux) {
	d.intakeH.RegisterHealthRoutes(mux)
}

// RegisterAuthedRoutes wires the operator-facing read surface
// (host / alert / tree). ModeIntake skips this.
func (d *Detection) RegisterAuthedRoutes(mux *http.ServeMux) {
	if d.operatorH == nil {
		return
	}
	d.operatorH.RegisterRoutes(mux)
}
