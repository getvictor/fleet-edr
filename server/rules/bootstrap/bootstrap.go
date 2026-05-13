package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jmoiron/sqlx"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
	"github.com/fleetdm/edr/server/rules/internal/operator"
	"github.com/fleetdm/edr/server/rules/internal/service"
)

// Deps bundles what New needs to wire the rules context. cmd/main
// owns the *sqlx.DB handle and shares it across every context's
// bootstrap.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger

	// RegistryOptions threads operator-configured allowlists into the
	// rule constructors.
	RegistryOptions api.RegistryOptions

	// Audit is the operator-action recorder. Optional: today no route
	// inside the rules context emits audit rows; the field is wired so
	// the follow-on application-control change can plug into it without
	// touching the wiring layer.
	Audit identityapi.AuditRecorder
	// AuthZ is the authorization chokepoint every privileged operator
	// route gates on. Required. cmd/main wires identityCtx.AuthZ().
	AuthZ identityapi.AuthZ
}

// Rules is the handle cmd/main holds for the rules bounded context.
type Rules struct {
	svc          *service.Service
	operatorH    *operator.Handler
	appControlSt *appcontrol.Store
	db           *sqlx.DB
	logger       *slog.Logger
}

// New wires the rules context. Does NOT apply the schema (call
// ApplySchema for that).
func New(deps Deps) (*Rules, error) {
	if deps.DB == nil {
		return nil, errors.New("rules bootstrap: DB is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if deps.AuthZ == nil {
		return nil, errors.New("rules bootstrap: AuthZ is required")
	}

	rules := catalog.New(deps.RegistryOptions)
	svc := service.New(rules, logger)

	opH := operator.New(svc, deps.AuthZ, logger)
	opH.SetAudit(deps.Audit)
	return &Rules{
		svc:          svc,
		operatorH:    opH,
		appControlSt: appcontrol.NewStore(deps.DB),
		db:           deps.DB,
		logger:       logger,
	}, nil
}

// ApplySchema runs the DDL statements rules owns and seeds the
// per-tenant `Default` application control policy. Idempotent
// (CREATE TABLE IF NOT EXISTS + INSERT IGNORE on the seed). No
// cross-context FKs; ordering with other contexts' ApplySchema is
// not load-bearing.
func (r *Rules) ApplySchema(ctx context.Context) error {
	if err := ApplySchema(ctx, r.db); err != nil {
		return err
	}
	// Seed the per-tenant Default policy after the table exists. The
	// "default" tenant id is the wave-1 scaffolding value; wave-2
	// MSSP work will iterate over real tenants here.
	if err := r.appControlSt.EnsureDefaultPolicy(ctx, "default"); err != nil {
		return fmt.Errorf("rules seed default app control policy: %w", err)
	}
	return nil
}

// ApplySchema is the package-level form: applies rules' DDL against
// the given DB without requiring a fully constructed *Rules. Used by
// server/testdb so tests can apply every context's schema without
// faking out each bootstrap's service dependencies.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("rules ApplySchema: db must not be nil")
	}
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("rules schema apply: %w", err)
		}
	}
	return nil
}

// ContentService exposes the public api.RuleProvider. detection.Engine
// (still living at server/detection/) consumes this to load its rule
// set at start.
func (r *Rules) ContentService() api.RuleProvider { return r.svc }

// Catalog exposes the public api.Lister. The operator handler inside
// rules consumes this internally; nothing outside rules calls it
// today.
func (r *Rules) Catalog() api.Lister { return r.svc }

// ApplicationControlStore exposes the appcontrol store handle so the
// REST handler (and tests) can reach it without re-importing the
// internal/appcontrol package directly. Returns the api-level
// interface rather than the concrete *appcontrol.Store so the
// internal type does not leak across bounded-context boundaries
// (ADR-0004). The concrete implementation also satisfies the
// interface, so existing tests inside rules/ still get the same
// values back.
func (r *Rules) ApplicationControlStore() api.ApplicationControlStore { return r.appControlSt }

// RegisterAuthedRoutes wires the operator-facing routes:
//
//	GET  /api/rules
//	GET  /api/attack-coverage
//
// Caller wraps in identity Session + CSRF middleware before mounting.
// rules has no public agent-facing routes, so RegisterPublicRoutes
// does not exist.
func (r *Rules) RegisterAuthedRoutes(mux *http.ServeMux) {
	r.operatorH.RegisterRoutes(mux)
}

// CatalogOnly returns just the rule catalog, without wiring the
// operator routes. Exposed for tooling that doesn't have a DB handle
// (notably tools/gen-rule-docs which builds the markdown page from
// rule documentation at compile time).
func CatalogOnly(opts api.RegistryOptions) api.Lister {
	rules := catalog.New(opts)
	return catalogList(rules)
}

// catalogList satisfies api.Lister by reading from a captured rule
// slice. Avoids dragging the service constructor into the
// gen-rule-docs path.
type catalogList []api.Rule

func (c catalogList) List() []api.RuleMetadata {
	out := make([]api.RuleMetadata, 0, len(c))
	for _, r := range c {
		out = append(out, api.RuleMetadata{
			ID:         r.ID(),
			Techniques: r.Techniques(),
			Doc:        r.Doc(),
		})
	}
	return out
}
