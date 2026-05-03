package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
	"github.com/fleetdm/edr/server/rules/internal/operator"
	"github.com/fleetdm/edr/server/rules/internal/policy"
	"github.com/fleetdm/edr/server/rules/internal/service"
)

// ActiveHostsLister enumerates host_ids the policy fan-out should
// target. cmd/main supplies a closure that resolves
// endpoint.Service().ActiveHostIDs at call time so the bidirectional
// dependency between rules and endpoint resolves without a stateful
// setter.
type ActiveHostsLister = service.ActiveHostsLister

// CommandInserter inserts a single command row keyed on host_id.
// Today cmd/main passes response/api.Service.Insert as a method
// value satisfying this closure shape.
type CommandInserter = service.CommandInserter

// Deps bundles what New needs to wire the rules context. cmd/main
// owns the *sqlx.DB handle and shares it across every context's
// bootstrap.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger

	// RegistryOptions threads operator-configured allowlists into the
	// rule constructors.
	RegistryOptions api.RegistryOptions

	// ActiveHostsLister + CommandInserter are paired: both nil disables
	// the fan-out path (use case: docs generator, fleet-edr-ingest);
	// both non-nil enables it. An asymmetric pair is a config error.
	ActiveHostsLister ActiveHostsLister
	CommandInserter   CommandInserter
}

// Rules is the handle cmd/main holds for the rules bounded context.
type Rules struct {
	svc       *service.Service
	operatorH *operator.Handler
	db        *sqlx.DB
	logger    *slog.Logger
}

// New wires the rules context. Does NOT apply the schema (call
// ApplySchema for that).
func New(deps Deps) (*Rules, error) {
	if deps.DB == nil {
		return nil, errors.New("rules bootstrap: DB is required")
	}
	if (deps.ActiveHostsLister == nil) != (deps.CommandInserter == nil) {
		return nil, errors.New("rules bootstrap: ActiveHostsLister and CommandInserter must be set together (or both nil)")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	policyStore := policy.NewStore(deps.DB)
	rules := catalog.New(deps.RegistryOptions)
	svc := service.New(policyStore, rules, deps.ActiveHostsLister, deps.CommandInserter, logger)

	return &Rules{
		svc:       svc,
		operatorH: operator.New(svc, logger),
		db:        deps.DB,
		logger:    logger,
	}, nil
}

// ApplySchema runs the DDL statements rules owns. Idempotent
// (CREATE TABLE IF NOT EXISTS + INSERT IGNORE for the seed row). No
// cross-context FKs; ordering with other contexts' ApplySchema is
// not load-bearing.
func (r *Rules) ApplySchema(ctx context.Context) error {
	return ApplySchema(ctx, r.db)
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

// PolicyService exposes the public api.PolicyService for cross-context
// callers. cmd/main passes this into endpoint/bootstrap.Deps so the
// post-enroll fan-out goroutine can call ActiveCommandPayload.
func (r *Rules) PolicyService() api.PolicyService { return r.svc }

// ContentService exposes the public api.RuleProvider. detection.Engine
// (still living at server/detection/) consumes this to load its rule
// set at start.
func (r *Rules) ContentService() api.RuleProvider { return r.svc }

// Catalog exposes the public api.Lister. The operator handler inside
// rules consumes this internally; nothing outside rules calls it
// today.
func (r *Rules) Catalog() api.Lister { return r.svc }

// RegisterAuthedRoutes wires the operator-facing routes:
//
//	GET  /api/policy
//	PUT  /api/policy
//	GET  /api/rules
//	GET  /api/attack-coverage
//
// Caller wraps in identity Session + CSRF middleware before mounting.
// rules has no public agent-facing routes, so RegisterPublicRoutes
// does not exist.
func (r *Rules) RegisterAuthedRoutes(mux *http.ServeMux) {
	r.operatorH.RegisterRoutes(mux)
}

// CatalogOnly returns just the rule catalog, without wiring the policy
// store or operator routes. Exposed for tooling that doesn't have a
// DB handle (notably tools/gen-rule-docs which builds the markdown
// page from rule documentation at compile time).
func CatalogOnly(opts api.RegistryOptions) api.Lister {
	rules := catalog.New(opts)
	// service.New panics without a policy store; catalog-only callers
	// don't go through service.New. Return a thin api.Lister whose
	// List walks the rule slice directly.
	return catalogList(rules)
}

// catalogList satisfies api.Lister by reading from a captured rule
// slice. Avoids dragging the policy store into the gen-rule-docs path.
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
