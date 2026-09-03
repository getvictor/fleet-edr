package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

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

// batchTally accumulates what one batch's evaluation should record ONCE THE BATCH IS ACKNOWLEDGED.
//
// Nothing is written while evaluating, and that is the whole design. A batch that fails is nacked and replayed whole, so a counter
// incremented during evaluation counts a retried batch twice; #631 measured roughly 130 materialization retries a minute from one
// host under a sustained condition, so that is not a rounding error. Handing the tally back to the caller lets it be recorded once,
// after the acknowledgement that says the batch will not come round again.
type batchTally struct {
	monitor map[monitorKey]int
}

type monitorKey struct{ ruleID, hostID, severity string }

// addMonitorMatch records one monitor-mode match. Severity is the RESOLVED severity, after any override, so the counter labels a
// match with the severity the alert would have carried.
func (t *batchTally) addMonitorMatch(ruleID, hostID, severity string) {
	if t.monitor == nil {
		t.monitor = make(map[monitorKey]int)
	}
	t.monitor[monitorKey{ruleID: ruleID, hostID: hostID, severity: severity}]++
}

// snapshot flattens the tally into the published shape, sorted so a caller's writes and logs are deterministic across runs.
func (t *batchTally) snapshot() rulesapi.MonitorTally {
	if len(t.monitor) == 0 {
		return nil
	}
	out := make(rulesapi.MonitorTally, 0, len(t.monitor))
	for k, count := range t.monitor {
		out = append(out, rulesapi.MonitorMatch{RuleID: k.ruleID, HostID: k.hostID, Severity: k.severity, Count: count})
	}
	slices.SortFunc(out, func(a, b rulesapi.MonitorMatch) int {
		return cmp.Or(strings.Compare(a.RuleID, b.RuleID), strings.Compare(a.HostID, b.HostID), strings.Compare(a.Severity, b.Severity))
	})
	return out
}

// routeOutcome is what happened to one finding once its resolved mode was applied. It exists because "not alerted" was one bucket
// and covered two unrelated things: a mode holding the finding back, and an alert that already existed. An operator reading a
// suppressed count wants to know which, since the first is a configuration they chose and the second is the deduplication working.
//
// Zero is deliberately not a bucket, so an error return (which carries no outcome) cannot be miscounted as one.
type routeOutcome int

const (
	// routeAlerted: a new alert row was written.
	routeAlerted routeOutcome = iota + 1
	// routeSuppressed: the resolved mode was monitor or disabled, so no alert was attempted.
	routeSuppressed
	// routeDuplicate: the mode was alert and the insert deduplicated against an alert that already existed.
	routeDuplicate
)
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
	always []int
	// declaredTypes is each rule's declared event types, by the same index as rules. Cached here because Doc() builds a fresh
	// Documentation (slice included) on every call, which is fine at load and wasteful per batch.
	declaredTypes [][]string
	store         *mysql.Store
	// ruleReader is what RULES read the graph through: the store, wrapped so a failed read is retryable rather than isolated like
	// a broken rule (issue #798). The engine's own reads (alert persistence, dedup) use store directly, since a failure there is
	// already surfaced to the caller and must not acquire a rules-context sentinel.
	ruleReader   api.GraphReader
	logger       *slog.Logger
	metrics      api.MetricsRecorder
	modeResolver rulesapi.RuleModeResolver
	// evalStats is the durable sink for per-rule evaluation statistics (issue #774). Optional: nil records nothing.
	evalStats rulesapi.RuleEvalStatsRecorder
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
	// Built once here, not per batch: it is one interface value with no per-call allocation, which keeps the non-allocating
	// dispatch the concrete store handle exists for.
	return &Engine{store: s, ruleReader: &retryableGraphReader{inner: s}, logger: logger, tracer: otel.Tracer(tracerName)}
}

// SetMetrics installs the OTel counter hook. Safe to call after New.
func (e *Engine) SetMetrics(m api.MetricsRecorder) { e.metrics = m }

// SetModeResolver installs the per-host rule-mode resolver (issue #459). It routes each finding by the (rule, host) resolved mode:
// disabled drops it, monitor records an observability signal without persisting an alert, alert persists (applying a severity
// override).
//
// Nil (the default) applies each rule's own declared default with no override (issue #764), NOT alert unconditionally. A rule that
// declares nothing still alerts, so this is the pre-config behavior for every hand-written rule; a rule that declares monitor must
// not start alerting merely because no configuration surface is wired.
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
	e.declaredTypes = make([][]string, len(e.rules))
	for i, r := range e.rules {
		types := r.Doc().EventTypes
		e.declaredTypes[i] = types
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
// repeatedly without Evaluate() seeing duplicates.
//
// Accepts an inline interface so detection/internal/engine doesn't
// have to import rules/bootstrap; the rules.api.RuleProvider
// interface is the canonical implementation.
func (e *Engine) LoadActive(cs interface{ ActiveRules() []rulesapi.Rule }) {
	e.rules = append(e.rules[:0], cs.ActiveRules()...)
	e.reindex()
}

// Evaluate runs the rules that consume the batch's event types against it, per rulesFor: a rule is invoked only when the batch
// carries at least one event of a type it declares, and a rule declaring none is invoked for every batch.
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
func (e *Engine) Evaluate(ctx context.Context, events []api.Event) (rulesapi.MonitorTally, error) {
	live := filterSnapshotEvents(events)
	// One scope for the whole batch, so rules deriving the same thing from the same events derive it once (issue #794). What a rule
	// DERIVES stays opaque to the engine: that belongs to the rules context, which owns both the store and the read. The one thing
	// the engine does read back is the per-rule count of chains declined for incomplete ancestry, which is a map of primitives and
	// so crosses the context boundary without naming a rules-owned type (issue #829). It is
	// created unconditionally because it allocates nothing until a rule actually derives something, and it is discarded when this
	// call returns, so concurrent batches share nothing.
	scope := &rulesapi.BatchScope{}
	// One tally for the batch, returned to the caller to record after the acknowledgement. See batchTally.
	tally := &batchTally{}
	// One statistics accumulator for the batch, recorded from a defer so every exit path reports the work it did: a hard error
	// mid-loop, a retryable miss after the loop, and success. Recorded HERE rather than handed back like the tally, because
	// unlike a monitor match an evaluation is not something a replay must avoid counting twice; see RuleEvalStat's doc. Handing
	// it back would also lose it on exactly the path it matters most, since a batch ending in a retryable miss is never
	// acknowledged and the caller's record-after-ack step never runs.
	var stats rulesapi.RuleEvalStats
	defer func() { e.recordEvalStats(ctx, stats) }()
	var pendingMiss error
	for _, i := range e.rulesFor(live) {
		rule := e.rules[i]
		err := e.evaluateRule(ctx, rule, e.declaredTypes[i], live, scope, tally, &stats)
		if err == nil {
			continue
		}
		if !errors.Is(err, rulesapi.ErrRetryBatch) {
			// The batch will be nacked and replayed, so the tally is discarded: whatever it holds will be counted by the
			// attempt that succeeds.
			return nil, err
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
	if pendingMiss != nil {
		// Same reasoning as the hard error above: a retryable miss nacks the batch, so this attempt's matches are not the ones
		// to record.
		return nil, pendingMiss
	}
	return tally.snapshot(), nil
}

// distinctEventTypes returns the event types a batch carries, in first-seen order.
//
// The scratch array is stack-allocated: there are 13 event types in the wire schema, so a real batch never exceeds it and the
// linear scan is over at most 16 strings, allocating nothing.
//
// A batch is not obliged to be well formed, though. Intake accepts up to MaxIngestEventsPerRequest events and validates event_type
// only as non-empty, so an authenticated host can send a batch whose every event carries a distinct junk type. The linear scan is
// quadratic in that case, so once the scratch fills this switches to a set and the cost becomes linear again.
func distinctEventTypes(events []api.Event, present []string) []string {
	var seen map[string]struct{}
	for _, ev := range events {
		if seen != nil {
			if _, dup := seen[ev.EventType]; dup {
				continue
			}
			seen[ev.EventType] = struct{}{}
			present = append(present, ev.EventType)
			continue
		}
		if slices.Contains(present, ev.EventType) {
			continue
		}
		present = append(present, ev.EventType)
		if len(present) == cap(present) {
			seen = make(map[string]struct{}, 2*cap(present))
			for _, t := range present {
				seen[t] = struct{}{}
			}
		}
	}
	return present
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
	var scratch [16]string
	present := distinctEventTypes(live, scratch[:0])

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

// consumesAny reports whether any event in the batch is of a type the rule declares. A rule declaring nothing consumes everything,
// matching the fail-open direction the index takes.
func consumesAny(declared []string, events []api.Event) bool {
	if len(declared) == 0 {
		return true
	}
	for _, ev := range events {
		if slices.Contains(declared, ev.EventType) {
			return true
		}
	}
	return false
}

// evaluateRule opens a per-rule span carrying rule_id (observability-instrumentation spec) so detection latency and alert counts
// can be grouped by rule in downstream dashboards. The span is annotated with alert_count after the rule returns; on rule-evaluate
// failure the span records the error and the loop continues (per-rule isolation). Returns a non-nil error ONLY when alert
// persistence fails or the rule reported a retryable rulesapi.ErrProcessNotYetMaterialized: other rule-evaluation errors are
// logged + swallowed so a buggy rule doesn't block the rest.
func (e *Engine) evaluateRule(
	ctx context.Context, rule rulesapi.Rule, declared []string, live []api.Event, scope *rulesapi.BatchScope, tally *batchTally,
	stats *rulesapi.RuleEvalStats,
) (err error) {
	// Scope the batch to the rule's target platforms (ADR-0018): a macOS-only rule never sees a Windows event. Checked BEFORE the
	// span is opened, because a rule left with nothing to evaluate did not run, and emitting a span for it reports work that never
	// happened and inflates per-rule span volume by the whole cross-platform mismatch.
	scoped := platformScopedEvents(rule.Platforms(), live)
	if len(scoped) == 0 {
		return nil
	}
	// Dispatch decided on the WHOLE batch, so in a mixed-platform batch it can select a rule on an event that rule cannot see: a
	// macOS rule reading exec, dispatched because a Windows exec was present, then handed only the macOS events of other types.
	// Re-check against what the rule actually sees. The length comparison is the cheap way to ask "did scoping drop anything":
	// platformScopedEvents returns the input slice verbatim when every event matched and a strictly shorter copy otherwise, so
	// equal length means nothing was filtered and the index's decision already applied to exactly these events. That is every
	// batch on a single-platform fleet, so this costs nothing until there is something for it to catch.
	if len(scoped) != len(live) && !consumesAny(declared, scoped) {
		return nil
	}

	ctx, span := e.tracer.Start(ctx, "detection.rule.evaluate",
		trace.WithAttributes(attribute.String("rule_id", rule.ID())))
	defer span.End()

	// Counted from HERE, not from the caller's loop, so the durable statistics and the span agree by construction on what "this
	// rule ran" means. The two early returns above are the reason: a rule the platform scope left with nothing to see did not run,
	// and this file already decided that such a rule gets no span. Timing it in the loop instead would count those as
	// zero-duration evaluations and drag every cross-platform rule's mean toward nothing, which is precisely backwards for a
	// figure whose job is to find the expensive rule. Duplicating the scope check in the loop would work and would be a second
	// copy of a decision that has already drifted once (issue #829).
	start := time.Now()
	// Set where the engine decides this evaluation was retryable, and read by the defer below. NOT derived from the named return:
	// a rule may report a retryable miss ALONGSIDE findings it did resolve (see rulesapi.Rule.Evaluate's contract), those findings
	// are still persisted, and a persistence failure then overwrites the named err with its own error. Classifying that would
	// record zero misses for an evaluation that genuinely missed, and the miss is the counter an operator reads to find the rule
	// driving the retries (issue #833 review).
	var evalRetryable bool
	defer func() {
		elapsed := time.Since(start).Nanoseconds()
		// One entry per rule per batch, appended rather than merged, because rulesFor sorts and compacts its indices so a rule
		// is evaluated exactly once per batch.
		*stats = append(*stats, rulesapi.RuleEvalStat{
			RuleID:      rule.ID(),
			Evaluations: 1,
			EvalNs:      elapsed,
			MaxEvalNs:   elapsed,
			// A retryable outcome is an attempt that cost its time and could not decide, and it drives the replay this counter
			// exists to attribute to a rule.
			RetryableMisses: boolToCount(evalRetryable),
		})
	}()

	// Stamped from a defer, so every path reports what it did rather than only the paths that reach the end. Dashboards grouping
	// by rule_id need a consistent attribute set, and there are three ways out of this function: a rule error, a persistence
	// failure partway through the findings, and success. The failure path is the one that motivated moving this: it used to leave
	// the span reporting 0/0 while findings before it had genuinely been raised or suppressed, so the work already done vanished
	// from the trace at exactly the moment someone would be reading it. The counters start at zero, which is the honest answer
	// for a rule that produced nothing.
	var alerted, suppressed, duplicates int
	// Chains this rule declined because an ancestor had no record, counted as the delta across its own evaluation so a
	// batch-wide scope still reports per-rule (issue #829). Without it the decline is invisible: a rule that reports nothing
	// because ancestry was incomplete looks exactly like a rule with nothing to report, which is the documented way a detection
	// rots unnoticed. Read here rather than at the call site because this span is already labelled with rule_id.
	//
	// A SPAN attribute and not a metric counter, deliberately, and it is worth being precise about what that costs. A nacked
	// batch is replayed whole, so a chain declined in an attempt that is later nacked is recorded again on the next attempt's
	// span; issue #631 measured roughly 130 retries a minute from one host under a sustained condition, so the absolute count of
	// declines across spans can exceed the number of chains actually given up. A cumulative metric would have the same problem,
	// which is why MonitorTally is handed back to be recorded only after the acknowledgement.
	//
	// What makes the per-attempt form sufficient here is that the requirement asks for this to be measurable against the rule's
	// OWN alert volume, and alert_count below is measured on this same span, under the identical retry semantics. Both numbers
	// inflate by the same replay factor, so the ratio an operator actually reads is unaffected even though neither absolute is a
	// count of distinct events. Read as a rate against alert_count it answers the question; read as "chains lost today" it does
	// not, and that is the reason it is an attribute on a span an operator already reads next to those counts rather than a
	// standalone total presented as authoritative.
	//
	// The scope is shared by every rule in the batch, so this reads the entry for THIS rule rather than a batch total. No delta
	// against a pre-evaluation reading is needed: rulesFor sorts and Compacts its indices, so a rule is evaluated exactly once
	// per batch and its entry cannot already hold another of its own declines.
	defer func() {
		span.SetAttributes(
			attribute.Int("alert_count", alerted),
			attribute.Int("suppressed_count", suppressed),
			attribute.Int("duplicate_count", duplicates),
			attribute.Int("ancestry_incomplete_count", scope.AncestryIncompleteCounts()[rule.ID()]),
		)
	}()

	findings, err := evaluate(ctx, rule, scoped, e.ruleReader, scope)
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
		// The single point where the engine judges an evaluation retryable, which is why the statistics read it from here rather
		// than re-deriving it from a return value that later code reassigns.
		evalRetryable = true
	}
	techniques := rule.Techniques()
	// Read once per rule per batch rather than per finding: it is a type assertion, but so is the reason declaredTypes is cached,
	// and a batch can carry many findings for one rule.
	ruleDefault := rulesapi.DefaultModeOf(rule)
	// Attribution rides the alert the rule produces (issue #765). Read from the RULE, never from the finding, so that a rule
	// cannot credit someone else for its match or drop the credit entirely: the Detection Rule License obligation the imported
	// corpus carries would otherwise be satisfied only by rules that chose to satisfy it.
	//
	// AlertOriginOf rather than OriginOf, because a projection's findings carry a rule id that is not the projection's own and
	// so has an author this rule cannot speak for. See its doc.
	origin := rulesapi.AlertOriginOf(rule)

	// alert_count counts findings that were ROUTED TO A NEW ALERT, not findings the rule returned. Those were the same number until
	// the vendored corpus landed in monitor mode (issue #764); now most findings are suppressed, and counting what the rule
	// returned would have every dashboard grouping by rule_id report alerts that were never raised. The other two carry the rest,
	// so the three still sum to what the rule found rather than losing that when they stopped being equal.
	//
	// They are three counters rather than two because "not alerted" covered both a mode holding the finding back and an alert that
	// already existed, and on a rule in alert mode with a standing condition the second happens on every batch. Under two counters
	// that rule reported a climbing suppressed_count with nothing suppressing it, which is a question an operator cannot answer by
	// looking at their own configuration.
	//
	// NOTE ON COVERAGE: the suppressed arm is asserted by unit tests, which reach it without a store. The duplicate arm is not:
	// persistFinding needs a real store, and asserting the span from the integration package would mean installing a global tracer
	// provider from tests that run in parallel, which is the race the per-Engine tracer exists to avoid. It maps the same `created`
	// flag that already gates the alert log and edr.alerts.created, so it is correct by construction rather than by test, and that
	// is worth knowing rather than assuming.
	for _, f := range findings {
		outcome, err := e.routeFinding(ctx, rule.ID(), ruleDefault, f, techniques, origin, tally)
		if err != nil {
			span.RecordError(err)
			return err
		}
		switch outcome {
		case routeAlerted:
			alerted++
		case routeSuppressed:
			suppressed++
		case routeDuplicate:
			duplicates++
		}
	}
	return retryableMiss
}

// evaluate runs one rule, handing it the batch scope when it asks for one.
//
// The optional interface is checked here rather than at registration because it costs a single type assertion per rule per batch,
// which is nothing beside the work the rule is about to do, and keeping it out of Register means a rule cannot be registered as one
// kind and evaluated as another.
func evaluate(
	ctx context.Context, rule rulesapi.Rule, events []api.Event, gr api.GraphReader, scope *rulesapi.BatchScope,
) ([]api.Finding, error) {
	if scoped, ok := rule.(rulesapi.ScopedRule); ok {
		return scoped.EvaluateScoped(ctx, scope, events, gr)
	}
	return rule.Evaluate(ctx, events, gr)
}

// routeFinding applies the resolved mode to a single finding before persistence (issue #459): a `disabled` (rule, host) drops the
// finding, `monitor` records an observability signal without persisting an alert, and `alert` persists, applying any severity
// override. Keeping this off persistFinding keeps the mode policy in one place and persistFinding focused on the insert.
//
// ruleDefault is the mode the RULE declares for itself (issue #764), and it is what applies when no setting matches. It is also
// what applies when no mode resolver is wired at all, which matters: a deployment or a test with no detection-config service must
// not alert on a rule whose author declared monitor, since that is precisely the case the declaration exists to cover. A rule that
// declares nothing yields alert here, so nothing about an existing rule changes.
// It reports what happened to the finding, so the caller can annotate its span with what was actually raised rather than with what
// the rule returned.
func (e *Engine) routeFinding(
	ctx context.Context, ruleID string, ruleDefault rulesapi.DetectionRuleMode, f api.Finding, techniques []string,
	origin string, tally *batchTally,
) (routeOutcome, error) {
	mode, severityOverride := ruleDefault, ""
	if e.modeResolver != nil {
		mode, severityOverride = e.modeResolver.ResolveRuleMode(ruleID, f.HostID, ruleDefault)
	}
	// Resolved before the switch so the monitor counter and a persisted alert label the finding with the SAME severity. A monitor
	// setting can carry an override, and applying it only on the persist path below left the two series describing one rule at two
	// severities, which defeats the comparison the counter exists for.
	if severityOverride != "" {
		f.Severity = severityOverride
	}

	switch mode {
	case rulesapi.DetectionRuleModeDisabled:
		return routeSuppressed, nil
	case rulesapi.DetectionRuleModeMonitor:
		// Counted, then logged at DEBUG. This was an INFO line per match, which was proportionate when monitor was a state an
		// operator set deliberately on one noisy rule. Issue #764 made it the default for most of the catalog, and several of
		// those rules match commonplace commands, so an INFO per match is fleet-scale log amplification: every `id` on every host,
		// re-emitted whenever a batch is retried, since only alert persistence is deduplicated. The counter is the medium built
		// for a high-frequency per-rule signal, and it is also the one an operator needs to decide whether to promote the rule.
		tally.addMonitorMatch(ruleID, f.HostID, f.Severity)
		e.logger.DebugContext(ctx, "detection rule matched in monitor mode (no alert)",
			"rule", ruleID, "host", f.HostID, "severity", f.Severity, "title", f.Title)
		return routeSuppressed, nil
	case rulesapi.DetectionRuleModeAlert:
		// Fall through to the severity-override + persist path below.
	}
	created, err := e.persistFinding(ctx, f, techniques, origin)
	if err != nil {
		return 0, err
	}
	if !created {
		return routeDuplicate, nil
	}
	return routeAlerted, nil
}

// persistFinding inserts a single finding as an alert, stamping it
// with the rule's ATT&CK techniques and attribution and emitting the new-alert log
// line + metric only when the insert wasn't deduped away. Extracted
// from Evaluate so that method stays under the project
// cognitive-complexity cap.
//
// Finding.Source defaults to AlertSourceDetection when blank so
// catalog rules don't need to set it; the application-control block
// rule overrides it explicitly.
// It reports whether an alert was newly CREATED, which is not the same as whether persistence succeeded: an alert deduplicated on
// insert is a success that raised nothing, and a span or counter that treats the two alike reports alerts nobody received.
func (e *Engine) persistFinding(ctx context.Context, f api.Finding, techniques []string, origin string) (bool, error) {
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
		Origin:      origin,
		ProcessID:   f.ProcessID,
		Subject:     f.Subject,
		Techniques:  f.Techniques,
	}, f.EventIDs)
	if err != nil {
		return false, fmt.Errorf("persist detection alert for rule %s on host %s: %w", f.RuleID, f.HostID, err)
	}
	if !created {
		// Dedup-skip path: same rule + process + host. Evaluator noise.
		return false, nil
	}
	e.logger.InfoContext(ctx, "detection alert created",
		"rule", f.RuleID, "host", f.HostID, "severity", f.Severity, "title", f.Title)
	if e.metrics != nil {
		e.metrics.AlertCreated(ctx, f.RuleID, f.Severity)
	}
	return true, nil
}

// boolToCount renders a per-attempt flag as the additive count the statistics carry.
//
// A rule that was NOT retryable contributes 0 rather than being absent, so the stored evaluations and retryable_misses stay
// directly comparable: the ratio between them is the churn rate an operator reads.
func boolToCount(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// SetRuleEvalStatsRecorder installs the durable sink for per-rule evaluation statistics. Unset records nothing, which is what the
// fixture corpus, the replay harness and any deployment without a rules-context store want.
func (e *Engine) SetRuleEvalStatsRecorder(r rulesapi.RuleEvalStatsRecorder) { e.evalStats = r }

// recordEvalStats persists a batch's per-rule statistics, and swallows any failure.
//
// It cannot fail the batch and must not try. This runs from a defer on every exit path, including the ones that have already
// decided to nack, and the batch's real work is the detection: replaying it to save a counter would cost more than the counter is
// worth. A nil recorder is the normal case in tests.
func (e *Engine) recordEvalStats(ctx context.Context, stats rulesapi.RuleEvalStats) {
	if e.evalStats == nil || len(stats) == 0 {
		return
	}
	if err := e.evalStats.RecordRuleEvalStats(ctx, stats); err != nil {
		e.logger.ErrorContext(ctx, "record rule eval stats", "err", err, "rules", len(stats))
	}
}
