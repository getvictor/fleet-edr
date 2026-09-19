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
	"github.com/fleetdm/edr/server/response/internal/reachable"
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

	// Audit is the operator-action recorder. Optional: an action still commits its audit entry without one, and the entry then waits
	// in the outbox undelivered rather than being discarded. cmd/main wires identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder

	// AuthZ is the authorization chokepoint POST /api/commands and GET /api/commands/{id} gate on. Required. cmd/main wires
	// identityCtx.AuthZ().
	AuthZ identityapi.AuthZ

	// PrincipalLabel resolves a principal id (usr_<id> / svc_<id> / sys) to its display label, so a read of the reachable-address
	// set can name who last changed it rather than printing the principal id. Optional: without it the console falls back to the
	// id. cmd/main wires it over identity's Service.PrincipalLabel; a func keeps this context free of an identity-internal type.
	PrincipalLabel func(ctx context.Context, principalID string) (string, error)

	// AuditSweepInterval is how often this context's audit outbox sweep delivers entries a request could not, for every operator
	// action that commits one: containment changes, and command issuance and withdrawal. Optional: zero or negative means
	// auditoutbox.DefaultSweepInterval. Tests shorten it to watch a sweep deliver.
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
	authz     identityapi.AuthZ
	// principalLabel names who last changed the reachable-address set. Held from New because the handler that uses it is built
	// later, in EnableContainment.
	principalLabel func(ctx context.Context, principalID string) (string, error)
	// containmentH and containmentConverger are nil until EnableContainment wires host network containment.
	containmentH         *operator.ContainmentHandler
	containmentConverger *containment.Converger
	// reachableH is nil until EnableContainment wires it. The addresses a contained host may still reach are containment's
	// configuration, so they are mounted with it rather than separately: without containment there is nothing for them to widen.
	reachableH *operator.ReachableHandler
	// auditOutbox is where every operator action in this context commits its audit entry, containment changes and command issuance
	// and withdrawal alike, and auditDrain turns the entries into audit rows (issue #1070). The drain is nil without a recorder,
	// which only non-production wiring omits.
	auditOutbox        *auditoutbox.Store
	auditDrain         *auditoutbox.Drain
	auditSweepInterval time.Duration
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
	// Every operator action in this context commits its audit entry with the change (issue #1070); this drain turns the entries into
	// audit rows. Built here rather than where each action is wired because entries outlive the wiring that wrote them: a replica
	// configured without the containment routes still has to sweep what an earlier one left behind.
	responseOutbox := auditoutbox.NewStore(deps.DB, mysql.AuditOutboxTable)
	var responseAuditDrain *auditoutbox.Drain
	if deps.Audit != nil {
		var derr error
		if responseAuditDrain, derr = auditoutbox.NewDrain(responseOutbox, deps.Audit, "response actions", logger); derr != nil {
			return nil, fmt.Errorf("build response audit drain: %w", derr)
		}
	}
	svc.SetAuditOutbox(responseOutbox, responseAuditDrain)
	return &Response{
		svc:       svc,
		agentH:    agent.New(svc, logger),
		operatorH: opH,
		db:        deps.DB,
		logger:    logger,
		authz:     deps.AuthZ,

		principalLabel: deps.PrincipalLabel,

		auditOutbox:        responseOutbox,
		auditDrain:         responseAuditDrain,
		auditSweepInterval: deps.AuditSweepInterval,
	}, nil
}

// EnableContainment wires host network containment (#948): the containment routes and the catch-up that re-queues a host's state.
// cmd/main calls it once the endpoint context is open, since whether a host is enrolled, and when it last enrolled, are endpoint's.
// Until it is called the routes are not mounted and the catch-up does nothing.
func (r *Response) EnableContainment(enrolled api.HostEnrolledChecker, enrollments api.ActiveEnrollmentLister) {
	store := containment.NewStore(r.db)
	// One reachable service behind both the routes that edit the set and the containment path that delivers it, so an operator's
	// edit and the command a host receives cannot be built from different readers (issue #1059).
	reachableSvc := reachable.NewService(reachable.NewStore(r.db, r.auditOutbox), r.auditDrain)
	svc := containment.NewService(store, enrolled, r.svc.QueueTx, r.svc.Notify, r.svc.LatestOfType, r.auditOutbox,
		r.auditDrain, reachableSvc.Get)
	r.containmentH = operator.NewContainmentHandler(svc, r.authz, r.logger)
	r.containmentConverger = containment.NewConverger(store, r.svc.QueueTx, r.svc.Notify, enrollments, r.svc.LatestOfType,
		reachableSvc.Get, r.logger)
	r.reachableH = operator.NewReachableHandler(reachableSvc, r.authz, r.logger)
	if r.principalLabel != nil {
		r.reachableH.SetPrincipalLabelResolver(r.principalLabel)
	}
}

// RunAuditSweep delivers audit entries an operator action committed but whose request could not write out, until ctx is cancelled.
// It returns at once when no recorder is wired.
//
// Registered even where the containment routes are not mounted, because entries outlive the wiring that wrote them: a replica
// configured without the routes still has to drain what an earlier one left, and a sweep over an empty table costs one query a minute.
func (r *Response) RunAuditSweep(ctx context.Context) {
	if r.auditDrain == nil {
		return
	}
	r.auditDrain.SweepLoop(ctx, r.auditSweepInterval)
}

// Run starts the context's background loops and returns once ctx is cancelled and every one of them has stopped.
//
// One entry point rather than a method per loop, deliberately. A loop cmd/main has to remember to start separately is a loop that can
// be added and never started, and that is not hypothetical: the containment audit sweep was written, tested by calling it directly,
// and left unstarted in production until review caught it. A loop with nothing to do returns at once, so this is safe to call whatever
// is wired.
func (r *Response) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){r.RunContainmentCatchUp, r.RunAuditSweep} {
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
//	GET  /api/v1/containment/reachable-addresses
//	PUT  /api/v1/containment/reachable-addresses
//
// Caller wraps in identity.SessionMiddleware + identity.CSRFMiddleware
// before mounting.
func (r *Response) RegisterAuthedRoutes(mux httpserver.Router) {
	r.operatorH.RegisterRoutes(mux)
	if r.containmentH != nil {
		r.containmentH.RegisterRoutes(mux)
	}
	if r.reachableH != nil {
		r.reachableH.RegisterRoutes(mux)
	}
}
