package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// tracerName is the instrumentation-scope name for the OTel tracer the engine opens per-rule spans on, so downstream dashboards can
// group detection latency + alert counts by rule_id without parsing log lines. observability-instrumentation spec pins the rule_id +
// alert_count attribute shape.
const tracerName = "server/detection/engine"

// Engine manages a set of rules and evaluates them against event batches. The store handle is concrete (*mysql.Store) so rules reach
// api.GraphReader through the same interface and dispatch stays non-allocating.
type Engine struct {
	rules []rulesapi.Rule
	// dispatch maps an agent event type to the indices into rules of the rules that consume it, ascending. Rebuilt whenever the
	// rule set changes; read-only during Evaluate, which the processor may call concurrently.
	dispatch map[string][]int
	// always holds the indices of rules that declare no event types at all. They are invoked for every batch, because dispatch is
	// an optimisation and over-invoking a rule costs time while under-invoking it loses detections.
	always       []int
	store        *mysql.Store
	logger       *slog.Logger
	metrics      api.MetricsRecorder
	modeResolver rulesapi.RuleModeResolver
	// tracer is per-Engine rather than a package global so a test can install its own tracer on its own Engine instance without a data
	// race against another parallel test (a package-level var mutated by one test is read by evaluateRule in another). Production always
	// gets the same named tracer via New.
	tracer trace.Tracer
}

// New creates a detection engine backed by the given store.
func New(s *mysql.Store, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{store: s, logger: logger, tracer: otel.Tracer(tracerName)}
}

// SetMetrics installs the OTel counter hook. Safe to call after New.
func (e *Engine) SetMetrics(m api.MetricsRecorder) { e.metrics = m }

// SetModeResolver installs the per-host rule-mode resolver (issue #459). It routes each finding by the (rule, host) resolved mode:
// disabled drops it, monitor records an observability signal without persisting an alert, alert persists (applying a severity
// override). Nil (the default) means every rule alerts with no override, which is the pre-config behavior.
func (e *Engine) SetModeResolver(m rulesapi.RuleModeResolver) { e.modeResolver = m }

// Register adds a detection rule to the engine.
func (e *Engine) Register(r rulesapi.Rule) {
	e.rules = append(e.rules, r)
	e.reindex()
}

// reindex rebuilds the event-type dispatch index from the current rule set.
//
// Built eagerly on every rule-set change rather than lazily on first Evaluate, because the processor calls Evaluate from concurrent
// workers (issue #535) and a lazily-populated map would be a data race. Register and LoadActive run at bootstrap, before serving,
// so this stays on the cold path.
//
// The index is derived state: a pure function of the registered rules, rebuilt from them on load. It holds nothing a peer replica
// would need to serve the next request, so it is a per-replica cache in ADR-0010's sense and safe to lose.
func (e *Engine) reindex() {
	e.dispatch = make(map[string][]int, len(e.rules))
	e.always = e.always[:0]
	for i, r := range e.rules {
		types := r.Doc().EventTypes
		if len(types) == 0 {
			// A rule that declares nothing is invoked unconditionally. See the `always` field for why this fails open.
			e.always = append(e.always, i)
			continue
		}
		for _, t := range types {
			// A rule declaring the same type twice must not be evaluated twice for one batch.
			if idx := e.dispatch[t]; len(idx) > 0 && idx[len(idx)-1] == i {
				continue
			}
			e.dispatch[t] = append(e.dispatch[t], i)
		}
	}
}

// LoadActive replaces the engine's active rule set with what the
// rules.api.RuleProvider reports as active. Replace-semantics
// (rather than append) so a future hot-reload caller can invoke this
// repeatedly without Catalog() and Evaluate() seeing duplicates.
//
// Accepts an inline interface so detection/internal/engine doesn't
// have to import rules/bootstrap; the rules.api.RuleProvider
// interface is the canonical implementation.
func (e *Engine) LoadActive(cs interface{ ActiveRules() []rulesapi.Rule }) {
	e.rules = append(e.rules[:0], cs.ActiveRules()...)
	e.reindex()
}

// Catalog returns the metadata for every registered rule. Order matches registration order so callers can render deterministic output.
// Production main.go now goes through rules.api.Lister instead of this method, but the method stays so existing engine tests keep
// compiling.
func (e *Engine) Catalog() []rulesapi.RuleMetadata {
	out := make([]rulesapi.RuleMetadata, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, rulesapi.RuleMetadata{
			ID:         r.ID(),
			Techniques: r.Techniques(),
			Doc:        r.Doc(),
			Platforms:  r.Platforms(),
		})
	}
	return out
}

// Evaluate runs all registered rules against the event batch.
// Findings are persisted as alerts. Rule evaluation failures are
// logged and skipped, but alert persistence failures and retryable
// not-yet-materialized subject-process misses are returned so the
// caller can retry the batch.
//
// Snapshot exec events (issue #11: ESF baseline enumeration) are
// filtered out before rule evaluation. Those events describe
// processes that existed before the extension subscribed to ESF;
// they're stitched into the process tree by graph.Builder so an
// analyst can see Safari, Slack, Finder, etc., but they represent
// historical state, not new attacker activity. Letting rules see
// them would generate false positives every time the extension
// restarts.
// A retryable materialization miss from one rule does NOT stop the remaining rules: it is remembered and returned after every rule
// has run. Returning immediately meant an earlier rule stuck waiting on a process row that never materializes suppressed every rule
// after it in registration order for the whole of that rule's grace window, and the suppressed rules then got their first real
// evaluation only once their own (possibly shorter) grace had already elapsed, so a resolvable finding degraded to the silent skip
// and was lost. dns_c2_beacon is registered last and carries the tightest grace, so it was the one that lost alerts (issue #661).
// Non-retryable failures keep their existing semantics: a rule-evaluation error is logged and swallowed (per-rule isolation), and an
// alert-persistence error aborts immediately because the batch must be retried before any more findings are written.
func (e *Engine) Evaluate(ctx context.Context, events []api.Event) error {
	live := filterSnapshotEvents(events)
	var pendingMiss error
	for _, i := range e.rulesFor(live) {
		rule := e.rules[i]
		err := e.evaluateRule(ctx, rule, live)
		if err == nil {
			continue
		}
		if !errors.Is(err, rulesapi.ErrRetryBatch) {
			return err
		}
		// First retryable error wins, so the reported error names the rule that started the wait. The one exception is
		// specificity: a materialization miss is UPGRADED over an already-stored generic wait, because the processor reads
		// this error to decide whether to count edr.detection.materialization_retries. Without the upgrade, a rule that is
		// merely waiting (sensor_tamper waits out a recovery window) and happens to run earlier in registration order would
		// mask a real materialization miss on the same batch, and the counter an operator uses to spot a replica falling
		// behind would under-report exactly when it matters.
		if pendingMiss == nil ||
			(!errors.Is(pendingMiss, rulesapi.ErrProcessNotYetMaterialized) &&
				errors.Is(err, rulesapi.ErrProcessNotYetMaterialized)) {
			pendingMiss = err
		}
	}
	return pendingMiss
}

// rulesFor returns the indices of the rules to invoke for this batch: those consuming at least one event type the batch carries,
// plus any rule that declares no types. Ascending, so evaluation keeps registration order and the "first retryable error wins"
// precedence in Evaluate is unchanged.
//
// The declared types are a TRIGGER filter, not a batch filter. A dispatched rule still receives the whole batch, because a rule
// triggered by one type routinely reads another from the same batch: suspicious_exec triggers on a network_connect and reaches back
// for the exec that made it. Narrowing the batch to the trigger type would silently degrade that.
//
// Cost is proportional to the number of MATCHING rules rather than to the catalog size, which is what keeps a batch of a rarely
// consumed type cheap however many rules are registered.
func (e *Engine) rulesFor(live []api.Event) []int {
	// Stack-allocated: there are 13 event types in the wire schema, so a real batch never exceeds this. A malformed batch carrying
	// more simply spills to the heap, which is correct if slower.
	var scratch [16]string
	present := scratch[:0]
	for _, ev := range live {
		if !slices.Contains(present, ev.EventType) {
			present = append(present, ev.EventType)
		}
	}

	switch {
	case len(present) == 0:
		// An empty batch (or one that was entirely plumbing) can produce no findings, so only the unconditional rules run.
		return e.always
	case len(present) == 1 && len(e.always) == 0:
		// The common single-type batch: the index entry is already ascending and duplicate-free, so hand it back as-is and
		// allocate nothing.
		return e.dispatch[present[0]]
	}

	matched := make([]int, 0, len(e.always)+len(e.dispatch[present[0]]))
	matched = append(matched, e.always...)
	for _, t := range present {
		matched = append(matched, e.dispatch[t]...)
	}
	// A rule consuming two types both present in the batch appears twice; sorting restores registration order and Compact drops
	// the duplicates, so it is still evaluated exactly once.
	slices.Sort(matched)
	return slices.Compact(matched)
}

// evaluateRule opens a per-rule span carrying rule_id (observability-instrumentation spec) so detection latency and alert counts
// can be grouped by rule in downstream dashboards. The span is annotated with alert_count after the rule returns; on rule-evaluate
// failure the span records the error and the loop continues (per-rule isolation). Returns a non-nil error ONLY when alert
// persistence fails or the rule reported a retryable rulesapi.ErrProcessNotYetMaterialized: other rule-evaluation errors are
// logged + swallowed so a buggy rule doesn't block the rest.
func (e *Engine) evaluateRule(ctx context.Context, rule rulesapi.Rule, live []api.Event) error {
	// Scope the batch to the rule's target platforms (ADR-0018): a macOS-only rule never sees a Windows event. Checked BEFORE the
	// span is opened, because a rule left with nothing to evaluate did not run, and emitting a span for it reports work that never
	// happened and inflates per-rule span volume by the whole cross-platform mismatch.
	scoped := platformScopedEvents(rule.Platforms(), live)
	if len(scoped) == 0 {
		return nil
	}

	ctx, span := e.tracer.Start(ctx, "detection.rule.evaluate",
		trace.WithAttributes(attribute.String("rule_id", rule.ID())))
	defer span.End()
	// Stamp alert_count=0 up front so dashboards grouping by rule_id see a consistent attribute set across success and failure
	// paths. The success path below overrides this with the actual count; the rule-error early-return below would otherwise
	// leave alert_count unset and break aggregations that treat its absence as a missing-data signal.
	span.SetAttributes(attribute.Int("alert_count", 0))

	findings, err := rule.Evaluate(ctx, scoped, e.store)
	// A retryable materialization miss is reported ALONGSIDE whatever findings the rule did resolve in this batch, so the miss is
	// recorded but the findings are still persisted below rather than thrown away with the error. Only a non-retryable failure
	// discards the batch's findings: that path means the rule itself misbehaved, so its output is not trustworthy.
	var retryableMiss error
	if err != nil {
		span.RecordError(err)
		if !errors.Is(err, rulesapi.ErrRetryBatch) {
			e.logger.WarnContext(ctx, "detection rule evaluation failed", "rule", rule.ID(), "err", err)
			return nil
		}
		// A concurrently processed batch has not committed this event's subject process row yet (intra-replica workers since
		// issue #535, cross-replica claimers per ADR-0011). This is a retryable ordering condition, not a rule bug: fail the
		// batch so the processor nacks it and re-evaluates once the row lands. Alert dedup makes the re-run idempotent, and
		// the rules bound the retry with a grace window on the event's ingest age so an orphaned event cannot loop forever.
		retryableMiss = fmt.Errorf("rule %s: %w", rule.ID(), err)
	}
	span.SetAttributes(attribute.Int("alert_count", len(findings)))

	techniques := rule.Techniques()
	for _, f := range findings {
		if err := e.routeFinding(ctx, rule.ID(), f, techniques); err != nil {
			span.RecordError(err)
			return err
		}
	}
	return retryableMiss
}

// routeFinding applies the per-host resolved mode to a single finding before persistence (issue #459): a `disabled` (rule, host)
// drops the finding, `monitor` records an observability signal without persisting an alert, and `alert` (the default, and the case
// when no mode resolver is wired) persists, applying any severity override. Keeping this off persistFinding keeps the mode policy in
// one place and persistFinding focused on the insert.
func (e *Engine) routeFinding(ctx context.Context, ruleID string, f api.Finding, techniques []string) error {
	if e.modeResolver != nil {
		mode, severityOverride := e.modeResolver.ResolveRuleMode(ruleID, f.HostID)
		switch mode {
		case rulesapi.DetectionRuleModeDisabled:
			return nil
		case rulesapi.DetectionRuleModeMonitor:
			e.logger.InfoContext(ctx, "detection rule matched in monitor mode (no alert)",
				"rule", ruleID, "host", f.HostID, "severity", f.Severity, "title", f.Title)
			return nil
		case rulesapi.DetectionRuleModeAlert:
			// Fall through to the severity-override + persist path below.
		}
		if severityOverride != "" {
			f.Severity = severityOverride
		}
	}
	return e.persistFinding(ctx, f, techniques)
}

// persistFinding inserts a single finding as an alert, stamping it
// with the rule's ATT&CK techniques and emitting the new-alert log
// line + metric only when the insert wasn't deduped away. Extracted
// from Evaluate so that method stays under the project
// cognitive-complexity cap.
//
// Finding.Source defaults to AlertSourceDetection when blank so
// catalog rules don't need to set it; the application-control block
// rule overrides it explicitly.
func (e *Engine) persistFinding(ctx context.Context, f api.Finding, techniques []string) error {
	if f.Techniques == nil {
		f.Techniques = techniques
	}
	source := f.Source
	if source == "" {
		source = api.AlertSourceDetection
	}
	_, created, err := e.store.InsertAlert(ctx, api.Alert{
		HostID:      f.HostID,
		RuleID:      f.RuleID,
		Source:      source,
		Severity:    f.Severity,
		Title:       f.Title,
		Description: f.Description,
		ProcessID:   f.ProcessID,
		Subject:     f.Subject,
		Techniques:  f.Techniques,
	}, f.EventIDs)
	if err != nil {
		return fmt.Errorf("persist detection alert for rule %s on host %s: %w", f.RuleID, f.HostID, err)
	}
	if !created {
		// Dedup-skip path: same rule + process + host. Evaluator noise.
		return nil
	}
	e.logger.InfoContext(ctx, "detection alert created",
		"rule", f.RuleID, "host", f.HostID, "severity", f.Severity, "title", f.Title)
	if e.metrics != nil {
		e.metrics.AlertCreated(ctx, f.RuleID, f.Severity)
	}
	return nil
}
