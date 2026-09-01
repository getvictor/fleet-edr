package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
	"github.com/fleetdm/edr/server/rules/internal/export"
	"github.com/fleetdm/edr/server/rules/internal/operator"
	"github.com/fleetdm/edr/server/rules/internal/service"
	rulesmigrations "github.com/fleetdm/edr/server/rules/migrations"
)

// Deps bundles what New needs to wire the rules context. cmd/main owns the *sqlx.DB handle and shares it across every context's
// bootstrap.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger

	// Audit is the operator-action recorder. The application-control REST handler records a `application_control.rule_create` row on every
	// POST so SIEM dashboards can trace which rules an admin authored and which hosts the fan-out reached. Optional: when nil, the service
	// skips the Record call with a WARN log line (same posture identity uses on the async-audit fallback).
	Audit identityapi.AuditRecorder
	// AuthZ is the authorization chokepoint every privileged operator
	// route gates on. Required. cmd/main wires identityCtx.AuthZ().
	AuthZ identityapi.AuthZ

	// PrincipalLabel resolves a principal id (usr_<id> / svc_<id> / sys) to its display label (a user's email, a service account's
	// name, or "system") for the detection-config exclusions list's created_by column. Optional: when nil the handler returns the raw
	// principal id. cmd/main wires it over identity's Service.PrincipalLabel; a func keeps the rules context free of an identity-internal
	// import (ADR-0004), same posture as detection's UserExists dep.
	PrincipalLabel func(ctx context.Context, principalID string) (string, error)

	// CommandBatchInserter is the closure that enqueues `set_application_control` commands to a set of hosts in one batched
	// multi-row INSERT. The application-control fan-out path consults it on every rule mutation so every assigned host receives one
	// command per mutation in a couple of round trips rather than one per host. Optional: when nil, the application-control REST
	// routes are not mounted (the rules context still constructs cleanly so non-REST consumers like tools/gen-rule-docs keep working).
	CommandBatchInserter appcontrol.CommandBatchInserter
	// HostLister enumerates the deployment's enrolled hosts for the fan-out. cmd/main passes a wrapper over
	// detection.api.Service.ListHosts that projects each HostSummary down to its host_id. Same optional-when-nil contract as
	// CommandBatchInserter; nil disables the REST surface.
	HostLister appcontrol.HostLister
}

// Rules is the handle cmd/main holds for the rules bounded context.
type Rules struct {
	svc                *service.Service
	operatorH          *operator.Handler
	appControlH        *operator.AppControlHandler
	appControlSt       *appcontrol.Store
	appControlSvc      *appcontrol.Service
	detectionConfigSvc *detectionconfig.Service
	// detectionConfigStore is retained beyond the Service because the monitor-match counters are written by the detection
	// pipeline and pruned here, neither of which goes through the config Service's snapshot machinery.
	detectionConfigStore *detectionconfig.Store
	detectionConfigH     *operator.DetectionConfigHandler
	// retentionDays caps the age of recorded monitor-match counts. Zero prunes nothing.
	retentionDays int
	db            *sqlx.DB
	logger        *slog.Logger
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

	// Detection configuration (issue #459): per-host false-positive exclusions + per-rule mode/severity, DB-backed. The Service
	// resolves both for the rules (ExclusionResolver, consulted before a rule fires) and the engine (RuleModeResolver). Built here so
	// the rule set is constructed against the live resolver; the initial snapshot is loaded in ApplySchema once the tables exist.
	detectionConfigStore := detectionconfig.NewStore(deps.DB)
	detectionConfigSvc := detectionconfig.NewService(detectionConfigStore, nil, deps.Audit, logger)

	rules := catalog.New(detectionConfigSvc)
	svc := service.New(rules, detectionConfigSvc, logger)

	// Inject the per-rule exclusion-support map (issue #520) built from the live rule set so the create-exclusion API rejects a
	// (rule_id, match_type) pair no rule consults, and a rule_id that names no registered rule. Single source of truth: each rule's
	// SupportedExclusionMatchTypes(), the same set GET /api/rules surfaces to the admin UI.
	exclusionSupport := make(map[string][]api.ExclusionMatchType, len(rules))
	for _, r := range rules {
		exclusionSupport[r.ID()] = r.SupportedExclusionMatchTypes()
	}
	detectionConfigSvc.SetRuleExclusionSupport(exclusionSupport)

	opH := operator.New(svc, deps.AuthZ, logger)
	opH.SetAudit(deps.Audit)

	detectionConfigH := operator.NewDetectionConfig(detectionConfigSvc, deps.AuthZ, logger)
	if deps.PrincipalLabel != nil {
		detectionConfigH.SetPrincipalLabelResolver(deps.PrincipalLabel)
	}

	appControlStore := appcontrol.NewStore(deps.DB)
	var appControlSvc *appcontrol.Service
	var appControlH *operator.AppControlHandler
	if deps.CommandBatchInserter != nil && deps.HostLister != nil {
		appControlSvc = appcontrol.NewService(appcontrol.ServiceDeps{
			Store:    appControlStore,
			Commands: deps.CommandBatchInserter,
			Hosts:    deps.HostLister,
			Audit:    deps.Audit,
			Logger:   logger,
		})
		appControlH = operator.NewAppControl(appControlSvc, deps.AuthZ, logger)
	}
	return &Rules{
		svc:                  svc,
		detectionConfigStore: detectionConfigStore,
		operatorH:            opH,
		appControlH:          appControlH,
		appControlSt:         appControlStore,
		appControlSvc:        appControlSvc,
		detectionConfigSvc:   detectionConfigSvc,
		detectionConfigH:     detectionConfigH,
		db:                   deps.DB,
		logger:               logger,
	}, nil
}

// DefaultDetectionConfigRefreshInterval is how often a replica polls the detection-config version counter to pick up a config edit
// made on another replica. Matches the revocation-snapshot cadence: edits are infrequent + operator-driven and the poll is a single
// indexed-row read, so a tight interval is cheap and keeps cross-replica convergence far under the alert-evaluation timescale.
const DefaultDetectionConfigRefreshInterval = 5 * time.Second

// Run drives the rules context's background workers until ctx is cancelled: the detection-config snapshot refresh, which converges
// this replica with config mutations made on other replicas (ADR-0010 stateless server; mutations elsewhere only bump the shared
// version counter), and the monitor-match-count prune. cmd/main starts this in a goroutine alongside the other contexts' loops.
//
// The prune is NOT leader-gated, unlike the detection context's sweeps. Every RunIfLeader loop holds its advisory lock, and so a
// pooled connection, for the lifetime of the process, and the event processor sizes itself against what those loops leave behind
// (issue #722). The delete here is idempotent and needs no coordination: replicas racing on it delete rows the others already
// deleted, which costs one statement per replica per interval and buys back a permanently held connection.
func (r *Rules) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.detectionConfigSvc.RefreshLoop(ctx, DefaultDetectionConfigRefreshInterval)
	}()
	go func() {
		defer wg.Done()
		r.pruneMatchCountsLoop(ctx, DefaultMatchCountPruneInterval)
	}()
	wg.Wait()
}

// DefaultMatchCountPruneInterval is how often each replica sweeps monitor-match counts past the retention window. Hourly because
// the counters are bucketed by day: a tighter interval deletes nothing new, and a looser one only delays reclaiming rows that are
// already excluded from every read by their day.
const DefaultMatchCountPruneInterval = time.Hour

// SetRetentionDays sets the age cap the match-count prune applies AND the furthest back the read surface may claim to see. One
// entry point for both, because they are the same fact: rows past retention are deleted, so a read window wider than retention
// describes a period the data no longer covers. Zero (the default) prunes nothing, matching how the same knob disables the
// detection context's process-record retention runner.
//
// MUST be called before Run, for the prune half only. That loop reads `retentionDays` without synchronisation, which is safe
// only because starting the goroutine happens-after this write; cmd/main calls this from openContexts, well before it launches
// Run. Calling it afterwards would be a data race, and one that `go test -race` would not see unless a test happened to
// reproduce the ordering. The read-surface half carries no such constraint: the handler stores its cap atomically and starts at
// the constant maximum, so a later call simply narrows it.
func (r *Rules) SetRetentionDays(days int) {
	r.retentionDays = days
	// The same number bounds how far back the read surface may claim to see. Pruning at 7 days while the API advertises a 30-day
	// window would report a period the rows no longer cover, which is the misreport the echoed window exists to prevent.
	r.detectionConfigH.SetMatchCountCap(days)
}

// pruneMatchCountsLoop prunes on a ticker until ctx is cancelled. The first pass runs immediately rather than after a full
// interval, so a replica that restarts often still prunes; the sweep is idempotent, so an eager pass costs one no-op delete.
func (r *Rules) pruneMatchCountsLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r.pruneMatchCountsOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Rules) pruneMatchCountsOnce(ctx context.Context) {
	deleted, err := r.detectionConfigStore.PruneMatchCounts(ctx, r.retentionDays)
	switch {
	case err != nil && ctx.Err() != nil:
		// Shutdown cancelled the query; not a failure worth logging on the way out.
	case err != nil:
		r.logger.WarnContext(ctx, "rules: prune monitor match counts", "err", err)
	case deleted > 0:
		r.logger.InfoContext(ctx, "rules: pruned monitor match counts", "rows", deleted, "retention_days", r.retentionDays)
	}
}

// ApplySchema applies the rules context's goose migration corpus and seeds the `Default` application control policy. Idempotent
// (goose skips applied versions + INSERT IGNORE on the seed). No cross-context FKs; ordering with other contexts' ApplySchema is
// not load-bearing.
func (r *Rules) ApplySchema(ctx context.Context) error {
	if err := ApplySchema(ctx, r.db); err != nil {
		return err
	}
	// Seed the Default policy after the table exists.
	if err := r.appControlSt.EnsureDefaultPolicy(ctx); err != nil {
		return fmt.Errorf("rules seed default app control policy: %w", err)
	}
	// Load the initial detection-config snapshot now that the tables exist (New seeded an empty one so the resolver was safe to
	// hold during catalog construction).
	if err := r.detectionConfigSvc.Reload(ctx); err != nil {
		return fmt.Errorf("rules load detection config: %w", err)
	}
	return nil
}

// ApplySchema is the package-level form: applies rules' goose migration corpus against the given DB without requiring a fully
// constructed *Rules. Used by server/testdb so tests can apply every context's schema without faking out each bootstrap's service
// dependencies. Idempotent (goose skips already-applied versions), so a second call on an already-migrated DB is a no-op.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("rules ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, rulesmigrations.FS, runner.Options{
		Context:   "rules",
		TableName: "rules_goose_db_version",
	})
}

// ContentService exposes the public api.RuleProvider. detection.Engine (still living at server/detection/) consumes this to load its
// rule set at start.
func (r *Rules) ContentService() api.RuleProvider { return r.svc }

// DetectionConfigModeResolver exposes the per-host rule-mode resolver the detection engine consults to route each finding
// (alert / monitor / disabled) and apply a severity override. Backed by the live detection-config snapshot.
func (r *Rules) DetectionConfigModeResolver() api.RuleModeResolver { return r.detectionConfigSvc }

// MonitorMatchRecorder exposes the durable monitor-match counter the detection pipeline writes to after acknowledging a batch
// (issue #813). Same direction as the mode resolver above: the rules context owns the table, and detection consumes the narrow
// interface rather than reaching into it (ADR-0004).
func (r *Rules) MonitorMatchRecorder() api.MonitorMatchRecorder { return r.detectionConfigStore }

// Catalog exposes the public api.Lister. The operator handler inside rules consumes this internally; nothing outside rules calls it
// today.
func (r *Rules) Catalog() api.Lister { return r.svc }

// ApplicationControlStore exposes the appcontrol store handle so the REST handler (and tests) can reach it without re-importing the
// internal/appcontrol package directly. Returns the api-level interface rather than the concrete *appcontrol.Store so the internal
// type does not leak across bounded-context boundaries (ADR-0004). The concrete implementation also satisfies the interface,
// so existing tests inside rules/ still get the same values back.
func (r *Rules) ApplicationControlStore() api.ApplicationControlStore { return r.appControlSt }

// RegisterAuthedRoutes wires the operator-facing routes:
//
//	GET  /api/rules
//	GET  /api/attack-coverage
//	GET  /api/v1/app-control/policies                    (when CommandBatchInserter + HostLister are wired)
//	GET  /api/v1/app-control/policies/{id}               (when CommandBatchInserter + HostLister are wired)
//	POST /api/v1/app-control/policies/{id}/rules         (when CommandBatchInserter + HostLister are wired)
//
// Caller wraps in identity Session + CSRF middleware before mounting.
// rules has no public agent-facing routes, so RegisterPublicRoutes
// does not exist.
func (r *Rules) RegisterAuthedRoutes(mux httpserver.Router) {
	r.operatorH.RegisterRoutes(mux)
	if r.appControlH != nil {
		r.appControlH.RegisterRoutes(mux)
	}
	r.detectionConfigH.RegisterRoutes(mux)
}

// CatalogOnly returns just the rule catalog, without wiring the operator routes. Exposed for tooling that doesn't have a DB handle
// (notably tools/gen-rule-docs which builds the markdown page from rule documentation at compile time). A nil exclusion resolver is
// passed: tooling renders rule documentation, not live detection, so no configured exclusions apply.
//
// It goes through service.Service rather than a local api.Lister so the non-detection filter in Service.List is the ONE place that
// decides what the catalog surfaces contain. A second implementation here would have to repeat that filter, and the two would drift
// the first time only one was updated, leaving the generated docs describing a different rule set than GET /api/rules.
func CatalogOnly() api.Lister {
	return service.New(catalog.New(nil), nil, nil)
}

// PackSharedListsFile names the pack file holding shared list definitions. It is authored rather than generated, so the
// rule-file generator must preserve it; re-exported here because tooling lives outside server/rules and cannot import the
// catalog's internal package.
const PackSharedListsFile = catalog.SharedListsFile

// PrunePack removes rule files for rules that are no longer registered, preserving the authored shared-list file. Re-exported
// so tooling outside server/rules can reach the implementation, which lives where CI actually runs it.
func PrunePack(dir string, pack map[string][]byte) ([]string, error) {
	return export.Prune(dir, pack, PackSharedListsFile)
}

// ExportPack renders every registered detection THIS PROJECT AUTHORED as a declarative rule file, keyed by rule id (issue #757).
//
// Exposed here rather than from the internal export package because tooling (tools/gen-rule-pack) lives outside server/rules and
// so cannot import it, and because bootstrap is already the seam through which tooling reaches the catalog.
//
// Vendored rules are skipped (issue #764). Their declarative form already exists as the file this repository vendored, so
// rendering a second one in this project's format would put two representations of one rule on disk, and the two would say the
// same thing in different shapes. The per-rule export endpoint serves the vendored bytes for them instead, which is also the more
// useful artifact: an operator gets the upstream rule they can diff against SigmaHQ.
func ExportPack() (map[string][]byte, error) {
	authored := make([]api.RuleMetadata, 0, len(CatalogOnly().List()))
	for _, rm := range CatalogOnly().List() {
		if _, vendored := catalog.VendoredSource(rm.ID); vendored {
			continue
		}
		authored = append(authored, rm)
	}
	return export.Pack(authored, catalog.AuthoredFor)
}

// RefusedRule names an upstream rule the vendored corpus carries that this sensor does not run, and why.
type RefusedRule struct {
	// File is the vendored file, relative to the corpus root.
	File string
	// Reason names the telemetry or the feature that is missing, in the terms a re-sync would act on, rather than blaming the rule.
	Reason string
}

// ImportedRejections lists the vendored rules this sensor does not run (issue #764).
//
// Exposed here for the same reason ExportPack is: the docs generator lives outside server/rules and cannot reach the catalog
// directly. It goes in the generated reference rather than a start-up log line because it is a static fact about a corpus this
// repository vendored, and the person who needs it is asking "why is upstream's rule X not in my catalog" long after any boot log
// has scrolled away.
func ImportedRejections() []RefusedRule {
	rejected := catalog.ImportedRejections()
	out := make([]RefusedRule, 0, len(rejected))
	for _, r := range rejected {
		out = append(out, RefusedRule{File: r.File, Reason: r.Reason})
	}
	return out
}
