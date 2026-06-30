package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/coordination/leader"
	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/engine"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/intake"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/operator"
	"github.com/fleetdm/edr/server/detection/internal/pipeline"
	"github.com/fleetdm/edr/server/detection/internal/service"
	detectionmigrations "github.com/fleetdm/edr/server/detection/migrations"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
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

	// Pipeline cadences (Full mode only). A zero interval/cadence disables the corresponding loop.
	ProcessInterval time.Duration
	ProcessBatch    int
	// ProcessConcurrency is the number of in-process processor workers (issue #535). Unlike the cadence fields above, zero does NOT
	// disable the processor: it is clamped to a single worker (the historical single-goroutine behaviour).
	ProcessConcurrency   int
	StaleProcessTTL      time.Duration
	StaleProcessInterval time.Duration
	RetentionDays        int
	RetentionInterval    time.Duration
	// QueuePruneInterval is the cadence of the visibility event-queue sweep that removes acked rows (ADR-0015). Zero uses the
	// pipeline default (1 minute). Independent of RetentionDays: the queue is swept even when age-based retention is disabled.
	QueuePruneInterval time.Duration

	// Cross-context inputs (Full mode only).
	UserExists UserExists
	Metrics    api.MetricsRecorder
	// Audit is the operator-action recorder. Optional: nil disables audit emission for alert-status changes (existing tests pass nil
	// without ceremony). cmd/main wires identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder
	// AuthZ is the authorization chokepoint every privileged operator route gates on. Required in ModeFull. cmd/main wires
	// identityCtx.AuthZ(); intake-only mode (ModeIntake) does not register the operator handler so AuthZ may be nil there.
	AuthZ identityapi.AuthZ

	// IsDraining is the graceful-shutdown drain predicate the intake handler's /readyz consults. Optional: nil means readiness
	// reflects only the DB check. cmd/main wires the process DrainState's IsDraining so a SIGTERM flips /readyz to 503.
	IsDraining func() bool

	// Coordinator gates the single-replica periodic tasks (retention + process-TTL) so they run on exactly one replica. Optional:
	// nil runs them directly (single-replica deployments and tests). cmd/main wires a MySQL-advisory-lock coordinator.
	Coordinator leader.Coordinator

	// EventLog is the visibility work queue intake appends to and the processor claims from (ADR-0015). EventArchive is the durable
	// ClickHouse event lake intake writes to and correlation/evidence reads from. Both are REQUIRED in ModeFull and ModeIntake (the
	// intake handler fans out to both); cmd/main wires visibilityCtx.EventLog() / EventArchive().
	EventLog     visibilityapi.EventLog
	EventArchive visibilityapi.EventArchive
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

	if deps.EventLog == nil {
		return nil, errors.New("detection bootstrap: EventLog is required")
	}
	if deps.EventArchive == nil {
		return nil, errors.New("detection bootstrap: EventArchive is required")
	}

	store, err := mysql.New(deps.DB, deps.EventArchive, logger)
	if err != nil {
		return nil, fmt.Errorf("detection bootstrap: %w", err)
	}

	intakeH := intake.New(store, logger, deps.Build, deps.EventLog, deps.EventArchive)
	// Unconditional: a nil predicate is the documented "readiness reflects only the DB check" case (handleReadyz guards on
	// h.isDraining != nil), so there is no branch to leave untested here.
	intakeH.SetReadinessGate(deps.IsDraining)
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
		det.svc = service.New(store, query, intakeH, deps.EventLog, deps.UserExists, logger)
		if deps.AuthZ == nil {
			return nil, errors.New("detection bootstrap: AuthZ is required in ModeFull")
		}
		det.operatorH = operator.New(det.svc, deps.AuthZ, logger)
		det.operatorH.SetAudit(deps.Audit)

		processor := pipeline.NewProcessor(
			deps.EventLog,
			graph.NewBuilder(store, logger),
			det.engine,
			logger,
			deps.ProcessInterval,
			deps.ProcessBatch,
			deps.ProcessConcurrency,
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
		queuePrune := pipeline.NewQueuePrune(deps.EventLog, pipeline.QueuePruneOptions{
			Interval: deps.QueuePruneInterval,
			Logger:   logger,
		})
		det.pipe = pipeline.NewRunner(pipeline.RunnerOptions{
			Processor:   processor,
			ProcessTTL:  processTTL,
			Retention:   retention,
			QueuePrune:  queuePrune,
			DB:          deps.DB,
			Coordinator: deps.Coordinator,
		})
	} else {
		// Intake-only: still expose a service with the intake handler
		// so RegisterIngestRoutes works.
		det.svc = service.New(store, nil, intakeH, deps.EventLog, deps.UserExists, logger)
	}

	return det, nil
}

// ApplySchema runs the CREATE TABLE statements detection owns. Idempotent.
func (d *Detection) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, d.db)
}

// ApplySchema is the package-level form: applies detection's goose migration corpus against the given DB without requiring a fully
// constructed *Detection. Used by server/testdb so tests can apply every context's schema without faking out each bootstrap's
// service dependencies. Idempotent (goose skips already-applied versions), so a second call on an already-migrated DB is a no-op.
//
// The pre-goose additive-ALTER runner that bridged stale dev DBs is gone (#115): its ALTERs were already folded into the processes
// CREATE TABLE, so the goose baseline produces the full current schema. A dev DB that predates the fold is recreated with
// `task db:reset`, not auto-migrated.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("detection ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, detectionmigrations.FS, runner.Options{
		Context:   "detection",
		TableName: "detection_goose_db_version",
	})
}

// Service exposes the operator-facing api.Service. RecordHostSeen is
// the hot path response consumes via its Heartbeat closure.
func (d *Detection) Service() api.Service { return d.svc }

// SetMetrics wires the metrics recorder into the engine + intake + pipeline (processttl + retention) AFTER construction. Used by
// cmd/main to break the circular dependency between detectionCtx and metrics.New (the OfflineHosts gauge source needs detectionCtx;
// detectionCtx's engine + intake + pipeline need the recorder).
//
// It MUST be called before Run. The recorder is set-once construction-phase config that the running loops read (the pipeline runners
// read it on their immediate first sweep), so calling it concurrently with the loops is a data race (issue #561). cmd/main wires it
// before `go runDetection`; tests wire it through the helper before the loops launch.
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

// SetModeResolver wires the per-host rule-mode resolver into the engine AFTER construction (issue #459). cmd/main passes the rules
// context's detection-config service. No-op in ModeIntake (no engine). It is set-once construction-phase config, but unlike the metrics
// recorder (read by the pipeline runners on their immediate first sweep at Run start) the engine reads the mode resolver only while
// evaluating a claimed event batch. So it need only be wired before events are evaluated, not necessarily before Run: calling it after
// newDetection but before any events flow is safe (as the integration tests do); what is unsafe is calling it concurrently with the
// engine's evaluation of a batch.
func (d *Detection) SetModeResolver(m rulesapi.RuleModeResolver) {
	if d.engine != nil {
		d.engine.SetModeResolver(m)
	}
}

// Store exposes the persistence handle. Used by cmd/main for the
// retention DB-handle wiring (retention takes a *sqlx.DB directly).
func (d *Detection) Store() *mysql.Store { return d.store }

// LoadActive registers the active rule set with the engine. cmd/main
// calls this after rulesCtx is built. Skipped in ModeIntake (no engine). Like SetModeResolver it is set-once config the engine reads
// only while evaluating a claimed event batch, so wire it before events are evaluated, not necessarily before Run: after newDetection
// but before any events flow is fine (the engine has not read the rules yet); concurrent with the engine's evaluation of a batch is not.
// Tests that can fix the rule set at construction should pass it through the helper's opts (wired before Run); those whose rules depend
// on post-newDetection state (for example a just-inserted process id) call it after newDetection, before inserting the triggering events.
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
func (d *Detection) RegisterAuthedRoutes(mux httpserver.Router) {
	if d.operatorH == nil {
		return
	}
	d.operatorH.RegisterRoutes(mux)
}
