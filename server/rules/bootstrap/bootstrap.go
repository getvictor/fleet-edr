package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/migrations/runner"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
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

	// Corpus supplies rule definitions from the rulecontent context (ADR-0021): rulecontent produces content, rules consumes and
	// evaluates it. Optional. When nil, or when the stored corpus is empty or fails to load, the catalog falls back to the corpus
	// embedded in the binary, so a deployment that has not seeded storage behaves exactly as it did before (issue #766).
	Corpus rulecontentapi.Corpus
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

	// corpus supplies rule definitions from rulecontent (ADR-0021). Nil when the deployment runs the corpus embedded in the
	// build, in which case there is no stored content to poll and the refresh loop does not run.
	corpus rulecontentapi.Corpus
	// ruleSetObserver is notified after each successful rule-set install, so a consumer holding its own derived view of the rules
	// can rebuild it. cmd/main wires the detection engine's LoadActive here; keeping it a plain func leaves this context free of a
	// detection import (ADR-0004), the same posture as the PrincipalLabel and CommandBatchInserter deps.
	//
	// Set during wiring and read-only thereafter, like the other post-construction setters on this type. An earlier revision made
	// it atomic to allow registration after Run; review showed that does not buy safety, only the absence of a reported race. A
	// generation installed between the nil read and the store is never delivered, so the engine stays stale until the next publish,
	// which is worse than the ordering contract because nothing reports it. The contract is the honest version.
	ruleSetObserver func()
}

// New wires the rules context. Does NOT apply the schema (call
// ApplySchema for that).
func New(ctx context.Context, deps Deps) (*Rules, error) {
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

	// Built empty and filled below by installRuleSet, so the initial load and every later reload go through ONE definition of what
	// installing a rule set means. Three consumers derive from it and each goes stale silently on its own, which is not a fan-out
	// worth having two copies of.
	svc := service.New(nil, detectionConfigSvc, logger)

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
	r := &Rules{
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
		corpus:               deps.Corpus,
	}

	// Version 0: the initial set is stamped as not-from-storage even when it came from the store, because the version that produced
	// it has not been read yet and claiming one would be a guess. The first refresh tick reads the real version and, finding it
	// different, adopts the stored generation and stamps it correctly. One redundant load on the cold path buys an honest stamp.
	r.installRuleSet(catalog.NewWithCorpus(detectionConfigSvc, loadCorpus(ctx, deps.Corpus, logger)), 0)
	return r, nil
}

// installRuleSet puts a rule set in force and brings every consumer that derives from it along.
//
// There are THREE, and a miss in any one of them is silent, which is why they live here together rather than at each call site:
//
//  1. The service's own set, which GET /api/rules and the engine's loader read.
//  2. The exclusion-support map the detection-config service validates against. A stale map rejects a (rule_id, match_type) pair
//     for a rule that now exists, and accepts one naming a rule that no longer does.
//  3. Any observer, which is how the detection engine's derived dispatch indices get rebuilt.
//
// Returns the number of rules installed.
func (r *Rules) installRuleSet(rules []api.Rule, version int64) int {
	n := r.svc.Swap(rules, version)

	// Issue #520: built from the live rule set so the create-exclusion API rejects a (rule_id, match_type) pair no rule consults,
	// and a rule_id that names no registered rule. Single source of truth: each rule's SupportedExclusionMatchTypes(), the same set
	// GET /api/rules surfaces to the admin UI.
	exclusionSupport := make(map[string][]api.ExclusionMatchType, len(rules))
	for _, rule := range rules {
		exclusionSupport[rule.ID()] = rule.SupportedExclusionMatchTypes()
	}
	r.detectionConfigSvc.SetRuleExclusionSupport(exclusionSupport)

	if r.ruleSetObserver != nil {
		r.ruleSetObserver()
	}
	return n
}

// SetRuleSetObserver registers a callback invoked after each rule-set install, for a consumer that keeps its own view derived from
// the rules. cmd/main wires the detection engine's LoadActive.
//
// The callback runs synchronously on the refresh loop's goroutine, so it must not block: it is meant for rebuilding an in-memory
// index, which is what the engine does with it.
//
// MUST be called before Run. Registering afterwards races the refresh loop, and losing that race silently costs one generation:
// the install reads a nil observer and the consumer is not told, so it stays on the previous rule set until the next publish.
// cmd/main registers while wiring the contexts, before it starts any of their loops.
func (r *Rules) SetRuleSetObserver(observe func()) {
	r.ruleSetObserver = observe
}

// DefaultDetectionConfigRefreshInterval is how often a replica polls the detection-config version counter to pick up a config edit
// made on another replica. Matches the revocation-snapshot cadence: edits are infrequent + operator-driven and the poll is a single
// indexed-row read, so a tight interval is cheap and keeps cross-replica convergence far under the alert-evaluation timescale.
const DefaultDetectionConfigRefreshInterval = 5 * time.Second

// Run drives the rules context's background workers until ctx is cancelled: the detection-config snapshot refresh, which converges
// this replica with config mutations made on other replicas (ADR-0010 stateless server; mutations elsewhere only bump the shared
// version counter), and the per-rule counter prune, which sweeps BOTH counter tables (monitor match counts and evaluation
// statistics) in one pass. cmd/main starts this in a goroutine alongside the other contexts' loops.
//
// The prune is NOT leader-gated, unlike the detection context's sweeps. Every RunIfLeader loop holds its advisory lock, and so a
// pooled connection, for the lifetime of the process, and the event processor sizes itself against what those loops leave behind
// (issue #722). The delete here is idempotent and needs no coordination: replicas racing on it delete rows the others already
// deleted, which costs one statement per replica per interval and buys back a permanently held connection.
func (r *Rules) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		r.detectionConfigSvc.RefreshLoop(ctx, DefaultDetectionConfigRefreshInterval)
	}()
	go func() {
		defer wg.Done()
		r.pruneCountersLoop(ctx, DefaultCounterPruneInterval)
	}()
	go func() {
		defer wg.Done()
		r.CorpusRefreshLoop(ctx, DefaultCorpusRefreshInterval)
	}()
	wg.Wait()
}

// DefaultCorpusRefreshInterval is how often a replica polls the rule-corpus version counter to pick up content published on
// another replica, or by an operator between this replica's restarts.
//
// Longer than the detection-config cadence because the two answer different questions. A config edit retunes a rule an operator is
// watching right now and they expect the next alert to reflect it; publishing content is a deliberate change to what the fleet
// detects, where seconds of skew across replicas costs nothing and the reload rebuilds every rule and its indices rather than
// re-reading a settings snapshot.
const DefaultCorpusRefreshInterval = 30 * time.Second

// CorpusRefreshLoop converges this replica's rule set with content published elsewhere, following the detection-config snapshot
// pattern (ADR-0010: the compiled rule set is a per-replica cache, so a peer's publish is invisible here until we re-read).
//
// Each tick reads only the cheap version counter; the corpus itself is read, parsed and compiled only when the stored version
// differs from the one the loaded set was built from. Returns immediately when the deployment has no stored content to poll.
// Blocks until ctx is cancelled.
func (r *Rules) CorpusRefreshLoop(ctx context.Context, interval time.Duration) {
	if r.corpus == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.corpusRefreshTick(ctx) {
				return
			}
		}
	}
}

// corpusRefreshTick performs one convergence poll. Returns true to stop (ctx cancelled).
func (r *Rules) corpusRefreshTick(ctx context.Context) (stop bool) {
	current, err := r.corpus.Version(ctx)
	if err != nil {
		return r.handleCorpusRefreshErr(ctx, "version poll", err)
	}
	if current == r.svc.ActiveVersion() {
		return false
	}
	if _, err := r.Reload(ctx); err != nil {
		return r.handleCorpusRefreshErr(ctx, "reload", err)
	}
	return false
}

// handleCorpusRefreshErr decides what a refresh error means: a cancelled context is shutdown racing the poll, so the error is
// expected and the loop stops silently; otherwise the previous good rule set stays in force and the next tick retries.
func (r *Rules) handleCorpusRefreshErr(ctx context.Context, op string, err error) (stop bool) {
	if ctx.Err() != nil {
		return true
	}
	r.logger.WarnContext(ctx, "rules: rule-corpus "+op+" failed; keeping the rule set already in force", "err", err)
	return false
}

// Reload rebuilds the rule set from stored content and puts it in force, reporting how many rules are now active.
//
// On any failure the rule set already in force is LEFT ALONE and the error is returned. This is the one place the reload path
// deliberately differs from the startup path: at startup there is no previous set, so unusable content falls back to the corpus
// embedded in the build, whereas here that fallback would discard working content in favour of older content on a transient
// database error.
//
// Content that loads to nothing installs nothing, for the same reason: an operator who empties the corpus is not asking for a
// server with no detections. The loaded version is left unadvanced in that case, so the poll keeps re-reading while the corpus is
// empty, which is a rare and deliberate state rather than a steady one.
func (r *Rules) Reload(ctx context.Context) (int, error) {
	if r.corpus == nil {
		return 0, errors.New("rules: no rule corpus is configured")
	}

	// Version BEFORE documents, and the order is load-bearing. Two reads cannot be atomic across this interface, so a publish
	// landing between them yields a mismatched pair either way. Reading the version first pairs NEWER documents with an OLDER
	// version, so the next tick sees a difference and converges. The reverse order pairs older documents with the newer version,
	// which matches on the next tick and leaves the stale content in force indefinitely.
	version, err := r.corpus.Version(ctx)
	if err != nil {
		return 0, fmt.Errorf("read rule corpus version: %w", err)
	}
	docs, err := r.corpus.Documents(ctx)
	if err != nil {
		return 0, fmt.Errorf("read rule corpus: %w", err)
	}

	// Content the store HOLDS but that yields no runnable rules leaves the set in force alone, which is issue #766's stated
	// contract: "a malformed pack is rejected wholesale; the running set is untouched". The version is deliberately not recorded,
	// so the poll keeps seeing a difference and adopts the content as soon as it is fixed.
	//
	// This costs a real divergence, and it is worth naming rather than hiding. A replica that RESTARTS while unusable content is
	// stored has no set in force to keep, so it falls back to the corpus in its binary (loadCorpus) and runs something different
	// from its peers until the content is corrected. An earlier revision of this PR tried to close that by having everyone adopt
	// the binary's corpus and recording the version; review showed that is worse, because replicas mid-rolling-deployment embed
	// DIFFERENT corpora and would then stamp them with the same version, reporting convergence while running different rules. It
	// also silently replaces content an operator published.
	//
	// The real remedy is upstream: content that cannot run should never reach the store, which is what publish-time validation in
	// #767 is for. Until then the conservative choice is the contract, and issue #851 carries the cross-replica question.
	loaded, rejected, err := catalog.LoadCorpus(rulecontentapi.FS(docs), catalog.CorpusRoot)
	switch {
	case len(docs) == 0:
		r.logger.WarnContext(ctx, "rules: stored rule corpus is empty; keeping the rule set already in force", "version", version)
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("load rule corpus: %w", err)
	case len(loaded) == 0:
		// The loader refuses a rule it cannot run individually and reports that as success with nothing loaded, not as an error, so
		// this arrives on the happy path. Without it, publishing a corpus whose every document is refused would drop every corpus
		// detection while logging like an ordinary reload.
		r.logger.WarnContext(ctx, "rules: no document in the stored rule corpus could be loaded; keeping the rule set already in force",
			"version", version, "documents", len(docs), "refused", len(rejected))
		return 0, nil
	}

	n := r.installRuleSet(catalog.NewWithCorpus(r.detectionConfigSvc, loaded), version)
	// `rules` counts what came out of the corpus, matching the startup line so the two are comparable; `active` is the whole set in
	// force, which also carries the rules written natively. Reporting the total under the name the startup line uses for the corpus
	// count made the rule count appear to jump on the first reload with no content change, which live QA caught.
	r.logger.InfoContext(ctx, "rules: reloaded the rule corpus from storage",
		"version", version, "documents", len(docs), "rules", len(loaded), "refused", len(rejected), "active", n)
	return n, nil
}

// DefaultCounterPruneInterval is how often each replica sweeps the per-rule counter tables past the retention window. Hourly
// because both are bucketed by day: a tighter interval deletes nothing new, and a looser one only delays reclaiming rows that are
// already excluded from every read by their day.
//
// Named for counters rather than match counts because one sweep covers both tables. It was DefaultMatchCountPruneInterval when
// there was only one (issue #833 review).
const DefaultCounterPruneInterval = time.Hour

// SetRetentionDays sets the age cap BOTH counter prunes apply AND the furthest back the read surface may claim to see. One
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

// pruneCountersLoop prunes the per-rule counter tables on a ticker until ctx is cancelled. The first pass runs immediately rather
// than after a full interval, so a replica that restarts often still prunes; the sweep is idempotent, so an eager pass costs one
// no-op delete per table.
func (r *Rules) pruneCountersLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r.pruneCountersOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pruneCountersOnce prunes both per-rule counter tables in one pass.
//
// One sweep for both rather than a ticker each: they are pruned by the same retention knob at the same cadence, and both deletes
// are idempotent, so a second goroutine and a second ticker would buy nothing but another permanently parked goroutine per
// replica. They are reported separately because a failure on one says nothing about the other.
func (r *Rules) pruneCountersOnce(ctx context.Context) {
	r.pruneOnce(ctx, "monitor match counts", r.detectionConfigStore.PruneMatchCounts)
	r.pruneOnce(ctx, "rule eval stats", r.detectionConfigStore.PruneRuleEvalStats)
}

// pruneOnce runs one table's prune and reports it. what names the table in the log, so an operator reading a warning knows which
// sweep failed.
func (r *Rules) pruneOnce(ctx context.Context, what string, prune func(context.Context, int) (int64, error)) {
	deleted, err := prune(ctx, r.retentionDays)
	switch {
	case err != nil && ctx.Err() != nil:
		// Shutdown cancelled the query; not a failure worth logging on the way out.
	case err != nil:
		r.logger.WarnContext(ctx, "rules: prune "+what, "err", err)
	case deleted > 0:
		r.logger.InfoContext(ctx, "rules: pruned "+what, "rows", deleted, "retention_days", r.retentionDays)
	}
}

// loadCorpus returns the rule definitions to evaluate: the stored corpus when one is available, otherwise the corpus embedded in
// the binary.
//
// Falling back rather than failing, and the reason is the acceptance criterion this serves: a load failure must leave the server
// running detections rather than running none. At construction there is no previous good set to keep, so the embedded corpus IS the
// previous good set, and it is the same content the seed would have written. A deployment whose storage is empty, unreachable, or
// holding a malformed corpus therefore behaves exactly as it did before rule content acquired storage.
//
// Logged at WARN when it falls back for a REASON, and at neither when there is simply nothing stored: an unseeded corpus on first
// boot is the expected state, not a problem.
func loadCorpus(ctx context.Context, corpus rulecontentapi.Corpus, logger *slog.Logger) []api.Rule {
	if corpus == nil {
		return catalog.MustLoadImported()
	}
	docs, err := corpus.Documents(ctx)
	if err != nil {
		logger.WarnContext(ctx, "rules: stored rule corpus unreadable; using the corpus embedded in this build", "err", err)
		return catalog.MustLoadImported()
	}
	if len(docs) == 0 {
		return catalog.MustLoadImported()
	}
	loaded, rejected, err := catalog.LoadCorpus(rulecontentapi.FS(docs), catalog.CorpusRoot)
	if err != nil {
		logger.WarnContext(ctx, "rules: stored rule corpus failed to load; using the corpus embedded in this build",
			"documents", len(docs), "err", err)
		return catalog.MustLoadImported()
	}
	if len(loaded) == 0 {
		// Documents present and every one of them refused. This reached here as success with an empty set, so a deployment whose
		// stored corpus is entirely unrunnable started with NO corpus detections while the empty-store case above fell back. Both
		// are the same determinate state and must reach the same rule set, on this path and on the reload path alike.
		logger.WarnContext(ctx, "rules: no document in the stored rule corpus could be loaded; using the corpus embedded in this build",
			"documents", len(docs), "refused", len(rejected))
		return catalog.MustLoadImported()
	}
	logger.InfoContext(ctx, "rules: loaded rule corpus from storage",
		"documents", len(docs), "rules", len(loaded), "refused", len(rejected))
	return loaded
}

// EmbeddedCorpusFS and EmbeddedCorpusRoot expose the vendored corpus embedded in this build, for seeding rulecontent's storage.
//
// Re-exported through bootstrap because it is already the seam tooling reaches the catalog through (see ImportedRejections), and
// because catalog is an internal package. cmd/main passes these to rulecontent's seed; rulecontent itself takes an fs.FS and knows
// nothing about where it came from, so the supplier direction ADR-0021 sets is not inverted. Both go away when the corpus files
// move into rulecontent.
func EmbeddedCorpusFS() fs.FS { return catalog.ImportedCorpusFS() }

// EmbeddedCorpusRoot is the path prefix the embedded corpus is stored under, which the loader reads it back by.
const EmbeddedCorpusRoot = catalog.CorpusRoot

// EmbeddedCorpusIncludes reports whether a walked path is rule content rather than the packaging beside it, so a seed stores
// exactly what the loader will read.
func EmbeddedCorpusIncludes(p string) bool { return catalog.IsCorpusFile(p) }

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

// RuleEvalStatsRecorder exposes the durable per-rule evaluation-statistics sink the detection engine writes to (issue #774).
//
// Separate from MonitorMatchRecorder, and consumed by the ENGINE rather than the pipeline, because the two obey opposite recording
// rules: monitor matches are written only after the batch is acknowledged so a replay cannot count them twice, while evaluation
// statistics count every attempt and must be written even when the batch is nacked. See api.RuleEvalStat for the full reasoning.
func (r *Rules) RuleEvalStatsRecorder() api.RuleEvalStatsRecorder { return r.detectionConfigStore }

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
