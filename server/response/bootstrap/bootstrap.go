package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jmoiron/sqlx"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/agent"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/operator"
	"github.com/fleetdm/edr/server/response/internal/service"
)

// Heartbeat is the closure cmd/main supplies so response.Service
// can advance the host's last-seen-ns on every /api/commands poll
// without importing server/store (today's home of
// UpdateHostLastSeen) or detection (phase-5 home of RecordHostSeen).
// Returning an error is logged at WARN by the service; a heartbeat
// failure does NOT fail the poll because the agent already got its
// commands.
type Heartbeat = service.Heartbeat

// Deps bundles what New needs. cmd/main owns the *sqlx.DB handle and
// shares it across every context's bootstrap.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger

	// Heartbeat is optional; nil disables the per-poll last-seen
	// bump. Production wires cmd/main's `s.UpdateHostLastSeen`
	// closure; cmd/main wires it to detectionCtx.RecordHostSeen.
	Heartbeat Heartbeat

	// Audit is the operator-action recorder. Optional: nil disables
	// audit emission for command issuance. cmd/main wires
	// identityCtx.AuditRecorder().
	Audit identityapi.AuditRecorder

	// AuthZ is the authorization chokepoint POST /api/commands and
	// GET /api/commands/{id} gate on. Required. cmd/main wires
	// identityCtx.AuthZ().
	AuthZ identityapi.AuthZ
}

// Response is the handle cmd/main holds for the response bounded
// context.
type Response struct {
	svc       *service.Service
	agentH    *agent.Handler
	operatorH *operator.Handler
	db        *sqlx.DB
	logger    *slog.Logger
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
	return &Response{
		svc:       svc,
		agentH:    agent.New(svc, logger),
		operatorH: opH,
		db:        deps.DB,
		logger:    logger,
	}, nil
}

// ApplySchema runs the DDL statements response owns. Idempotent
// (CREATE TABLE IF NOT EXISTS). No cross-context FKs; ordering with
// other contexts' ApplySchema is not load-bearing.
func (r *Response) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, r.db)
}

// ApplySchema is the package-level form: applies response's DDL
// against the given DB without requiring a fully constructed
// *Response. Used by server/testdb so tests can apply every context's
// schema without faking out each bootstrap's service dependencies.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("response ApplySchema: db must not be nil")
	}
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("response schema apply: %w", err)
		}
	}
	return nil
}

// Service exposes the public api.Service for cross-context callers.
// endpoint and rules consume Service.Insert as a method value
// satisfying their CommandInserter closure types; cmd/main's metrics
// adapter consumes Service.CountPending.
func (r *Response) Service() api.Service { return r.svc }

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
//
// Caller wraps in identity.SessionMiddleware + identity.CSRFMiddleware
// before mounting.
func (r *Response) RegisterAuthedRoutes(mux *http.ServeMux) {
	r.operatorH.RegisterRoutes(mux)
}
