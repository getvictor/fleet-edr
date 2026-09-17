package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/auditoutbox"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/agent"
	"github.com/fleetdm/edr/server/response/internal/containment"
	"github.com/fleetdm/edr/server/response/internal/gateway"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/operator"
	"github.com/fleetdm/edr/server/response/internal/service"
	responsemigrations "github.com/fleetdm/edr/server/response/migrations"
)

// Heartbeat is the closure cmd/main supplies so response.Service can advance the host's last-seen-ns on every /api/commands poll
// without importing server/store (today's home of UpdateHostLastSeen) or detection (phase-5 home of RecordHostSeen). Returning an
// error is logged at WARN by the service; a heartbeat failure does NOT fail the poll because the agent already got its commands.
type Heartbeat = service.Heartbeat

// Deps bundles what New needs. cmd/main owns the *sqlx.DB handle and
// shares it across every context's bootstrap.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger

	// Heartbeat is optional; nil disables the per-poll last-seen bump. Production wires cmd/main's `s.UpdateHostLastSeen` closure;
	// cmd/main wires it to detectionCtx.RecordHostSeen.
	Heartbeat Heartbeat

	// Audit is the operator-action recorder. Optional: nil disables audit emission for command issuance. cmd/main wires
	// identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder

	// AuthZ is the authorization chokepoint POST /api/commands and GET /api/commands/{id} gate on. Required. cmd/main wires
	// identityCtx.AuthZ().
	AuthZ identityapi.AuthZ

	// AuditSweepInterval is how often the containment audit outbox sweep delivers entries a request could not. Optional: zero or
	// negative means auditoutbox.DefaultSweepInterval. Tests shorten it to watch a sweep deliver.
	AuditSweepInterval time.Duration
}

// Response is the handle cmd/main holds for the response bounded
// context.
type Response struct {
	svc       *service.Service
	agentH    *agent.Handler
	operatorH *operator.Handler
	db        *sqlx.DB
	logger    *slog.Logger
	audit     identityapi.AuditRecorder
	authz     identityapi.AuthZ
	// containmentH and containmentConverger are nil until EnableContainment wires host network containment.
	containmentH         *operator.ContainmentHandler
	containmentConverger *containment.Converger
	// containmentOutbox is where a containment change commits its audit entry, and containmentAuditDrain turns the entries into
	// audit rows (issue #1070). The drain is nil without a recorder, which only non-production wiring omits.
	containmentOutbox     *auditoutbox.Store
	containmentAuditDrain *auditoutbox.Drain
	auditSweepInterval    time.Duration
}

// New wires the response context. Does NOT apply the schema (call
// ApplySchema for that).
func New(deps Deps) (*Response, error) {
	if deps.DB == nil {
		return nil, errors.New("response bootstrap: DB is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if deps.AuthZ == nil {
		return nil, errors.New("response bootstrap: AuthZ is required")
	}
	store := mysql.NewStore(deps.DB)
	svc := service.New(store, deps.Heartbeat, logger)
	opH := operator.New(svc, deps.AuthZ, logger)
	opH.SetAudit(deps.Audit)
	// A containment change commits its audit entry with the change (issue #1070); this drain turns the entries into audit rows. Built
	// here rather than in EnableContainment because entries outlive the wiring that wrote them: a replica configured without the
	// containment routes still has to sweep what an earlier one left behind.
	containmentOutbox := auditoutbox.NewStore(deps.DB, containment.AuditOutboxTable)
	var containmentAuditDrain *auditoutbox.Drain
	if deps.Audit != nil {
		var derr error
		if containmentAuditDrain, derr = auditoutbox.NewDrain(containmentOutbox, deps.Audit, "host containment",
			logger); derr != nil {
			return nil, fmt.Errorf("build containment audit drain: %w", derr)
		}
	}
	return &Response{
		svc:       svc,
		agentH:    agent.New(svc, logger),
		operatorH: opH,
		db:        deps.DB,
		logger:    logger,
		audit:     deps.Audit,
		authz:     deps.AuthZ,

		containmentOutbox:     containmentOutbox,
		containmentAuditDrain: containmentAuditDrain,
		auditSweepInterval:    deps.AuditSweepInterval,
	}, nil
}

// EnableContainment wires host network containment (#948): the containment routes and the catch-up that re-queues a host's state.
// cmd/main calls it once the endpoint context is open, since whether a host is enrolled, and when it last enrolled, are endpoint's.
// Until it is called the routes are not mounted and the catch-up does nothing.
func (r *Response) EnableContainment(enrolled api.HostEnrolledChecker, enrollments api.ActiveEnrollmentLister) {
	store := containment.NewStore(r.db)
	svc := containment.NewService(store, enrolled, r.svc.QueueTx, r.svc.Notify, r.svc.LatestOfType, r.containmentOutbox,
		r.containmentAuditDrain, r.logger)
	r.containmentH = operator.NewContainmentHandler(svc, r.authz, r.logger)
	r.containmentConverger = containment.NewConverger(store, r.svc.QueueTx, r.svc.Notify, enrollments, r.svc.LatestOfType,
		r.logger)
}

// RunContainmentAuditSweep delivers audit entries a containment change committed but whose request could not write out, until ctx is
// cancelled. It returns at once when no recorder is wired.
//
// Registered even where the containment routes are not mounted, because entries outlive the wiring that wrote them: a replica
// configured without the routes still has to drain what an earlier one left, and a sweep over an empty table costs one query a minute.
func (r *Response) RunContainmentAuditSweep(ctx context.Context) {
	if r.containmentAuditDrain == nil {
		return
	}
	r.containmentAuditDrain.SweepLoop(ctx, r.auditSweepInterval)
}

// Run starts the context's background loops and returns once ctx is cancelled and every one of them has stopped.
//
// One entry point rather than a method per loop, deliberately. A loop cmd/main has to remember to start separately is a loop that can
// be added and never started, and that is not hypothetical: the containment audit sweep was written, tested by calling it directly,
// and left unstarted in production until review caught it. A loop with nothing to do returns at once, so this is safe to call whatever
// is wired.
func (r *Response) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){r.RunContainmentCatchUp, r.RunContainmentAuditSweep} {
		wg.Go(func() { loop(ctx) })
	}
	wg.Wait()
}

// RunContainmentCatchUp re-queues hosts' containment states every containment.DefaultConvergeInterval until ctx is cancelled. It returns
// at once when containment is not enabled.
func (r *Response) RunContainmentCatchUp(ctx context.Context) {
	if r.containmentConverger == nil {
		return
	}
	r.containmentConverger.Loop(ctx, 0)
}

// ApplySchema applies response's goose migration corpus. Idempotent (goose skips already-applied versions). No cross-context FKs;
// ordering with other contexts' ApplySchema is not load-bearing.
func (r *Response) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, r.db)
}

// ApplySchema is the package-level form: applies response's goose migration corpus against the given DB without requiring a fully
// constructed *Response. Used by server/testdb so tests can apply every context's schema without faking out each bootstrap's
// service dependencies. Idempotent (goose skips already-applied versions), so a second call on an already-migrated DB is a no-op.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("response ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, responsemigrations.FS, runner.Options{
		Context:   "response",
		TableName: "response_goose_db_version",
	})
}

// Service exposes the public api.Service for cross-context callers. endpoint consumes Service.Insert and rules consumes
// Service.InsertBatch as method values satisfying their command-inserter closure types.
//
// cmd/main also takes Service.UndeliverableByHost as a method value and hands it to the detection context, which turns it into the
// host-health condition that tells an operator a host is not accepting commands (issue #732). That closed out the CountPending this
// interface used to carry: a fleet-wide pending total, written for an OTel gauge it was never wired to, and unable to answer the
// per-host question anyway. It was removed rather than wired.
func (r *Response) Service() api.Service { return r.svc }

// BuildControlGateway constructs the agent control-channel gateway for this context and wires the fast-path notifier so a command
// queued on this replica is pushed to a locally-held connection immediately. cmd/main supplies the cross-context dependencies (the
// host-token verifier from endpoint, the last-seen closure from detection), multiplexes the returned gateway's gRPC server onto the
// main HTTPS listener, and runs its watch loop. TLS is terminated once at that shared listener (or by the front proxy), so the gateway
// runs without its own transport credentials. The gateway uses the concrete service (which carries the gateway-only
// ListDeliverableForHosts query), so this stays inside the response context rather than widening the public api.Service.
func (r *Response) BuildControlGateway(verifier gateway.TokenVerifier, heartbeat gateway.Heartbeat) *gateway.Gateway {
	gw := gateway.New(gateway.Deps{
		Source:    r.svc,
		Verifier:  verifier,
		Heartbeat: heartbeat,
		Logger:    r.logger,
	})
	r.svc.SetNotifier(gw.Notify)
	return gw
}

// RegisterAgentRoutes wires the host-token-gated agent routes:
//
//	GET /api/commands
//	PUT /api/commands/{id}
//
// Caller wraps in endpoint.HostTokenMiddleware before mounting.
func (r *Response) RegisterAgentRoutes(mux *http.ServeMux) {
	r.agentH.RegisterRoutes(mux)
}

// RegisterAuthedRoutes wires the operator-facing routes:
//
//	POST /api/commands
//	GET  /api/commands/{id}
//	GET  /api/hosts/{host_id}/containment   (once EnableContainment is called)
//	POST /api/hosts/{host_id}/containment
//
// Caller wraps in identity.SessionMiddleware + identity.CSRFMiddleware
// before mounting.
func (r *Response) RegisterAuthedRoutes(mux httpserver.Router) {
	r.operatorH.RegisterRoutes(mux)
	if r.containmentH != nil {
		r.containmentH.RegisterRoutes(mux)
	}
}
