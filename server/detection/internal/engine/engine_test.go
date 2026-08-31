package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// stubRule is a no-op Rule so the engine has something to register
// without dragging in a production rule's allowlist + DB lookups.
type stubRule struct {
	id         string
	techniques []string
	// platforms overrides the rule's target platforms; nil defaults to darwin so existing tests behave as before the platform-scoping
	// change. received captures the events the most recent Evaluate saw and calls counts invocations, so the scoping test can assert
	// what a rule was (or was not) handed.
	platforms []rulesapi.Platform
	received  []api.Event
	calls     int
}

func (r *stubRule) ID() string           { return r.id }
func (r *stubRule) DisplayName() string  { return "Stub" }
func (r *stubRule) Techniques() []string { return r.techniques }
func (r *stubRule) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{
		Title:    r.DisplayName(),
		Severity: rulesapi.SeverityHigh,
	}
}
func (r *stubRule) Evaluate(_ context.Context, events []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	r.calls++
	r.received = events
	return nil, nil
}
func (r *stubRule) SupportedExclusionMatchTypes() []rulesapi.ExclusionMatchType { return nil }
func (r *stubRule) Platforms() []rulesapi.Platform {
	if r.platforms == nil {
		return []rulesapi.Platform{rulesapi.PlatformDarwin}
	}
	return r.platforms
}

func TestEngine_RegisterAccumulates(t *testing.T) {
	t.Parallel()
	e := New(nil, nil)
	e.Register(&stubRule{id: "a"})
	e.Register(&stubRule{id: "b", techniques: []string{"T1"}})
	cat := e.Catalog()
	assert.Len(t, cat, 2)
	ids := []string{cat[0].ID, cat[1].ID}
	assert.Equal(t, []string{"a", "b"}, ids,
		"Catalog returns rules in registration order")
	assert.Equal(t, []string{"T1"}, cat[1].Techniques)
}

// TestEngine_LoadActiveReplacesRuleSet pins the replace (not append) semantics: a hot-reload caller can invoke LoadActive repeatedly
// without the engine accumulating duplicates.
func TestEngine_LoadActiveReplacesRuleSet(t *testing.T) {
	t.Parallel()
	e := New(nil, nil)
	e.Register(&stubRule{id: "old-1"})
	e.Register(&stubRule{id: "old-2"})

	e.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "new"}}})

	cat := e.Catalog()
	assert.Len(t, cat, 1, "LoadActive replaces, never appends")
	assert.Equal(t, "new", cat[0].ID)
}

// stubProvider satisfies the inline interface LoadActive consumes.
type stubProvider struct{ rules []rulesapi.Rule }

func (s stubProvider) ActiveRules() []rulesapi.Rule { return s.rules }

func eventIDs(events []api.Event) []string {
	ids := make([]string, len(events))
	for i := range events {
		ids[i] = events[i].EventID
	}
	return ids
}

// spec:server-detection-rules-engine/platform-scoped-rule-evaluation/a-darwin-only-rule-does-not-see-windows-events
// spec:server-detection-rules-engine/platform-scoped-rule-evaluation/a-mixed-platform-batch-is-filtered-per-rule
// spec:server-detection-rules-engine/platform-scoped-rule-evaluation/an-event-without-a-platform-is-evaluated-as-darwin
//
// The engine hands each rule only the events whose platform is in the rule's declared set (ADR-0018). A darwin rule and a windows rule
// evaluating one mixed batch each see only their platform's events, and an event carrying no platform is scoped as darwin. Stubs return
// no findings, so persistFinding is never reached and a nil store is safe; the assertions read each stub's captured events + call count.
func TestEngine_Evaluate_ScopesEventsByPlatform(t *testing.T) {
	t.Parallel()
	darwinRule := &stubRule{id: "darwin-rule", platforms: []rulesapi.Platform{rulesapi.PlatformDarwin}}
	windowsRule := &stubRule{id: "windows-rule", platforms: []rulesapi.Platform{rulesapi.PlatformWindows}}
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{darwinRule, windowsRule}})

	batch := []api.Event{
		{EventID: "d", HostID: "h", TimestampNs: 1, EventType: "exec", Platform: "darwin", Payload: []byte("{}")},
		{EventID: "w", HostID: "h", TimestampNs: 2, EventType: "exec", Platform: "windows", Payload: []byte("{}")},
		{EventID: "legacy", HostID: "h", TimestampNs: 3, EventType: "exec", Payload: []byte("{}")}, // no platform -> darwin
	}
	require.NoError(t, e.Evaluate(context.Background(), batch))

	require.Equal(t, 1, darwinRule.calls)
	assert.ElementsMatch(t, []string{"d", "legacy"}, eventIDs(darwinRule.received),
		"the darwin rule sees the darwin event and the platform-less event normalized to darwin, not the windows event")
	require.Equal(t, 1, windowsRule.calls)
	assert.Equal(t, []string{"w"}, eventIDs(windowsRule.received), "the windows rule sees only the windows event")

	// A windows-only rule against an all-darwin batch has no matching events, so the engine skips it entirely (Evaluate never called).
	winOnly := &stubRule{id: "win-only", platforms: []rulesapi.Platform{rulesapi.PlatformWindows}}
	e2 := New(nil, nil)
	e2.LoadActive(stubProvider{rules: []rulesapi.Rule{winOnly}})
	require.NoError(t, e2.Evaluate(context.Background(), []api.Event{
		{EventID: "d", HostID: "h", TimestampNs: 1, EventType: "exec", Platform: "darwin", Payload: []byte("{}")},
	}))
	assert.Zero(t, winOnly.calls, "a rule with no matching-platform events in the batch is not evaluated")
}

// spec:observability-instrumentation/trace-propagation-through-the-request-pipeline/detection-spans-carry-rule-context
//
// Per-rule spans MUST carry at least rule_id and an alert count attribute so downstream dashboards can group detection latency
// by rule. The test registers a stub rule, installs an in-memory SpanRecorder via a LOCAL TracerProvider (without mutating
// otel.SetTracerProvider, which Copilot flagged as racy under parallel package tests), calls Engine.Evaluate, then walks the
// recorder's captured spans for one with rule_id == stub's id and asserts the alert_count attr is also present. stubRule returns
// zero findings so persistFinding is never reached (avoids needing a live mysql.Store); the test pins attribute presence and value,
// not non-zero counts: the alert-count contract is "the attr exists and is countable", and 0 is a valid count.
func TestEngine_Evaluate_PerRuleSpanCarriesRuleContext(t *testing.T) {
	t.Parallel()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	// Install the recording tracer on THIS Engine instance (not a package global) so parallel tests never race on shared tracer state:
	// evaluateRule reads e.tracer, so each test's Engine carries its own. No otel.SetTracerProvider call, so nothing global is mutated.
	e := New(nil, nil)
	e.tracer = tp.Tracer("server/detection/engine")
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "stub-rule-x"}}})

	// The batch has to carry an event the rule is actually handed. A rule left with nothing to evaluate no longer opens a span,
	// because the platform scope is checked first: a span for a rule that never ran reports work that did not happen. This test is
	// about what an emitted span carries, so it feeds one event and asserts on the span that results.
	require.NoError(t, e.Evaluate(t.Context(), []api.Event{{EventType: "exec", Platform: string(rulesapi.PlatformDarwin)}}))

	ended := rec.Ended()
	require.NotEmpty(t, ended, "evaluateRule MUST end at least one span per Evaluate call")
	var found bool
	for _, sp := range ended {
		var ruleID string
		var alertCount int64
		var sawAlertCountAttr bool
		for _, a := range sp.Attributes() {
			switch a.Key {
			case attribute.Key("rule_id"):
				ruleID = a.Value.AsString()
			case attribute.Key("alert_count"):
				alertCount = a.Value.AsInt64()
				sawAlertCountAttr = true
			}
		}
		if ruleID != "stub-rule-x" {
			continue
		}
		found = true
		assert.Equal(t, "detection.rule.evaluate", sp.Name(),
			"per-rule span MUST be named so dashboards can filter by operation")
		assert.True(t, sawAlertCountAttr, "alert_count attribute MUST be present so dashboards can sum across rules")
		assert.Equal(t, int64(0), alertCount, "stub rule returned no findings; alert_count MUST reflect that")
	}
	assert.True(t, found, "no recorded span carried rule_id=stub-rule-x; the rule_id attr is the spec's primary key")
}

// failingRule is a stub whose Evaluate always returns the configured error, so the tests below can pin which error classes the
// engine swallows versus propagates.
type failingRule struct {
	stubRule
	err error
}

func (r *failingRule) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	return nil, r.err
}

// TestEngine_Evaluate_PropagatesNotYetMaterialized pins the retry contract for the materialization race: an Evaluate error wrapping
// rulesapi.ErrProcessNotYetMaterialized must surface to the processor (which nacks and retries the batch), while an ordinary rule
// failure keeps the historical log-and-swallow isolation so one buggy rule cannot wedge the pipeline.
// spec:server-detection-rules-engine/retryable-evaluation-on-unmaterialized-subject-process/a-young-event-s-subject-process-row-is-missing
func TestEngine_Evaluate_PropagatesNotYetMaterialized(t *testing.T) {
	t.Parallel()

	// A rule is only evaluated when the batch has an event for its platform (ADR-0018), so these cases pass one darwin-scoped event
	// (no platform normalizes to darwin, matching the default-darwin stub) rather than a nil batch: with nil, platform scoping would
	// skip the rule and its error would never be produced.
	batch := []api.Event{{EventID: "e", HostID: "h", TimestampNs: 1, EventType: "exec", Payload: []byte("{}")}}

	t.Run("not-yet-materialized error fails the batch", func(t *testing.T) {
		t.Parallel()
		e := New(nil, nil)
		e.Register(&failingRule{
			stubRule: stubRule{id: "racy-rule"},
			err:      fmt.Errorf("event x references pid 7: %w", rulesapi.ErrProcessNotYetMaterialized),
		})
		err := e.Evaluate(t.Context(), batch)
		require.ErrorIs(t, err, rulesapi.ErrProcessNotYetMaterialized,
			"the sentinel must reach the processor so the batch is nacked and re-evaluated")
	})

	t.Run("ordinary rule failure is swallowed", func(t *testing.T) {
		t.Parallel()
		e := New(nil, nil)
		e.Register(&failingRule{stubRule: stubRule{id: "buggy-rule"}, err: errors.New("boom")})
		require.NoError(t, e.Evaluate(t.Context(), batch),
			"a non-retryable rule failure keeps per-rule isolation: logged, not batch-fatal")
	})
}

// TestEngine_Evaluate_AFailingRuleDoesNotSuppressLaterRules is the engine half of the issue #661 repro.
//
// TestEngine_Evaluate_MaterializationMissSurvivesAGenericWait pins which retryable cause reaches the processor when a batch
// produces both kinds.
//
// The processor branches on the SPECIFIC sentinel to decide whether to count edr.detection.materialization_retries, the counter an
// operator reads to spot a replica falling behind on the process graph (issue #631). Rules run in registration order and the first
// retryable error is the one kept, so a rule that is merely waiting (sensor_tamper waits out its recovery window and raises the
// generic ErrRetryBatch) would mask a real materialization miss from a rule registered after it, and the counter would under-report
// precisely when the condition it exists for is happening. Both orderings are asserted because registration order is not something
// this contract should depend on.
func TestEngine_Evaluate_MaterializationMissSurvivesAGenericWait(t *testing.T) {
	t.Parallel()

	generic := fmt.Errorf("sensor_tamper awaiting recovery window: %w", rulesapi.ErrRetryBatch)
	specific := fmt.Errorf("event x references pid 7: %w", rulesapi.ErrProcessNotYetMaterialized)

	cases := []struct {
		name  string
		first error
		last  error
	}{
		{"generic wait registered first", generic, specific},
		{"materialization miss registered first", specific, generic},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			batch := []api.Event{{EventID: "e", HostID: "h", TimestampNs: 1, EventType: "exec", Payload: []byte("{}")}}

			e := New(nil, nil)
			e.Register(&failingRule{stubRule: stubRule{id: "first-rule"}, err: tc.first})
			e.Register(&failingRule{stubRule: stubRule{id: "second-rule"}, err: tc.last})

			err := e.Evaluate(t.Context(), batch)

			require.ErrorIs(t, err, rulesapi.ErrRetryBatch, "either cause must still nack the batch")
			require.ErrorIs(t, err, rulesapi.ErrProcessNotYetMaterialized,
				"the materialization cause must survive so the processor still counts the retry")
		})
	}
}

// Rules are evaluated in registration order and the engine used to return on the first retryable miss, so every rule after the
// missing one was skipped for as long as that rule kept missing. A rule waiting on a process row that never materialises holds its
// own grace window open (30s for the subject-process rules), and the skipped rules only got their first real evaluation once that
// elapsed. dns_c2_beacon is registered last and carries the shortest grace (5s), so its own window was always already spent by then
// and its findings degraded to the silent skip.
//
// Every rule must now be evaluated regardless, with the miss reported afterwards so the processor still nacks the batch. The
// non-retryable case is the other half of the same contract: an ordinary rule failure keeps its historical log-and-swallow isolation
// and must not stop the rules after it either. Both cases assert the same invariant (a failing rule never suppresses its successors)
// and differ only in the error class and whether it reaches the processor, so they are one table.
// spec:server-detection-rules-engine/retryable-evaluation-on-unmaterialized-subject-process/a-retryable-miss-does-not-suppress-the-remaining-rules
func TestEngine_Evaluate_AFailingRuleDoesNotSuppressLaterRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ruleID  string
		err     error
		wantErr error // non-nil: the class the processor must see, so it nacks and re-evaluates.
	}{
		{
			name:    "retryable miss reaches the processor",
			ruleID:  "racy-rule",
			err:     fmt.Errorf("event x references pid 7: %w", rulesapi.ErrProcessNotYetMaterialized),
			wantErr: rulesapi.ErrProcessNotYetMaterialized,
		},
		{
			name:   "ordinary rule failure is swallowed",
			ruleID: "buggy-rule",
			err:    errors.New("boom"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			batch := []api.Event{{EventID: "e", HostID: "h", TimestampNs: 1, EventType: "exec", Payload: []byte("{}")}}

			e := New(nil, nil)
			e.Register(&failingRule{stubRule: stubRule{id: tc.ruleID}, err: tc.err})
			later := &stubRule{id: "later-rule"}
			e.Register(later)

			err := e.Evaluate(t.Context(), batch)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr,
					"the miss must still reach the processor so the batch is nacked and re-evaluated")
			} else {
				require.NoError(t, err, "a non-retryable rule failure keeps per-rule isolation: logged, not batch-fatal")
			}
			assert.Equal(t, 1, later.calls,
				"a rule registered after a failing rule must still be evaluated; skipping it burned its own grace window (issue #661)")
		})
	}
}

// typedRule is a stub that declares the event types it consumes, so the dispatch tests can assert which rules an event batch
// reaches. stubRule deliberately declares none (the fail-open case); this one declares.
type typedRule struct {
	stubRule
	eventTypes []string
}

func (r *typedRule) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: r.DisplayName(), Severity: rulesapi.SeverityHigh, EventTypes: r.eventTypes}
}

// eventOfType builds a darwin event of the given type. Named for what it does rather than for its first caller: most call sites
// pass dns_query, network_connect or fork, and the dispatch tests are precisely about which type a batch carries.
func eventOfType(eventType string) api.Event {
	return api.Event{EventType: eventType, Platform: string(rulesapi.PlatformDarwin)}
}

// spec:server-detection-rules-engine/a-rule-is-invoked-only-for-batches-carrying-an-event-type-it-consumes/a-rule-is-not-invoked-for-a-batch-it-cannot-act-on
//
// TestEngine_Evaluate_DispatchesOnlyRulesConsumingTheBatchesEventTypes is the dispatch contract: a rule is invoked when the batch
// carries at least one event type it declares, and is not invoked otherwise.
//
// This is what makes per-batch cost independent of catalog size. Measured against 2.55M real dev events, fork and exit are 28% of
// telemetry and no rule consumes either, while the four rules reading open, btm_launch_item_add, sensor_provider_transition and
// sensor_recovery_failed cover 52 events in that entire corpus yet were invoked on every batch.
func TestEngine_Evaluate_DispatchesOnlyRulesConsumingTheBatchesEventTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		batch  []api.Event
		want   []string // rule ids expected to be invoked
		absent []string
	}{
		{
			name:   "a single-type batch reaches only that type's rules",
			batch:  []api.Event{eventOfType("dns_query")},
			want:   []string{"dns"},
			absent: []string{"exec-only", "open-only", "multi"},
		},
		{
			name:   "a rule declaring several types is reached by any of them",
			batch:  []api.Event{eventOfType("network_connect")},
			want:   []string{"multi"},
			absent: []string{"exec-only", "dns", "open-only"},
		},
		{
			name:   "a mixed batch reaches the union",
			batch:  []api.Event{eventOfType("exec"), eventOfType("dns_query")},
			want:   []string{"exec-only", "dns", "multi"},
			absent: []string{"open-only"},
		},
		{
			// fork and exit are 28% of real telemetry and no rule consumes either, so this batch shape does no rule work at all.
			name:   "a batch no rule consumes reaches nothing",
			batch:  []api.Event{eventOfType("fork"), eventOfType("exit")},
			absent: []string{"exec-only", "dns", "open-only", "multi"},
		},
		{
			name:   "an empty batch reaches nothing",
			batch:  nil,
			absent: []string{"exec-only", "dns", "open-only", "multi"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rules := map[string]*typedRule{
				"exec-only": {stubRule: stubRule{id: "exec-only"}, eventTypes: []string{"exec"}},
				"dns":       {stubRule: stubRule{id: "dns"}, eventTypes: []string{"dns_query"}},
				"open-only": {stubRule: stubRule{id: "open-only"}, eventTypes: []string{"open"}},
				"multi":     {stubRule: stubRule{id: "multi"}, eventTypes: []string{"exec", "network_connect"}},
			}
			e := New(nil, nil)
			// Registration order is fixed so the assertions do not depend on map iteration order.
			e.LoadActive(stubProvider{rules: []rulesapi.Rule{
				rules["exec-only"], rules["dns"], rules["open-only"], rules["multi"],
			}})

			require.NoError(t, e.Evaluate(t.Context(), tc.batch))

			for _, id := range tc.want {
				assert.Equal(t, 1, rules[id].calls, "rule %q consumes a type in the batch and must be invoked", id)
			}
			for _, id := range tc.absent {
				assert.Zero(t, rules[id].calls, "rule %q consumes no type in the batch and must not be invoked", id)
			}
		})
	}
}

// spec:server-detection-rules-engine/a-rule-is-invoked-only-for-batches-carrying-an-event-type-it-consumes/a-rule-declaring-no-event-types-still-runs
//
// TestEngine_Evaluate_ARuleDeclaringNoEventTypesAlwaysRuns pins the fail-open direction.
//
// Dispatch is an optimisation, so the two ways of being wrong are not symmetric: invoking a rule that had nothing to do costs
// time, while skipping one that did have something to do loses a detection silently. A rule that declares nothing therefore runs
// for every batch rather than none.
func TestEngine_Evaluate_ARuleDeclaringNoEventTypesAlwaysRuns(t *testing.T) {
	t.Parallel()

	undeclared := &stubRule{id: "undeclared"} // stubRule.Doc() carries no EventTypes
	declared := &typedRule{stubRule: stubRule{id: "declared"}, eventTypes: []string{"open"}}
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{undeclared, declared}})

	require.NoError(t, e.Evaluate(t.Context(), []api.Event{eventOfType("dns_query")}))
	assert.Equal(t, 1, undeclared.calls, "a rule declaring nothing must still be invoked")
	assert.Zero(t, declared.calls, "a rule declaring only open must not be invoked for a dns_query batch")
}

// TestEngine_Evaluate_DispatchPreservesRegistrationOrder pins that dispatch hands rules back in registration order.
//
// Evaluate's error precedence depends on it: the first retryable error wins, so the error names the rule that started the wait.
// Reordering would change which rule the operator sees named.
func TestEngine_Evaluate_DispatchPreservesRegistrationOrder(t *testing.T) {
	t.Parallel()

	var order []string
	record := func(id string) *typedRule {
		r := &typedRule{stubRule: stubRule{id: id}, eventTypes: []string{"exec", "dns_query"}}
		return r
	}
	first, second, third := record("first"), record("second"), record("third")
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{first, second, third}})

	// A batch carrying BOTH types every rule declares, so each appears twice in the pre-merge candidate list.
	for _, i := range e.rulesFor([]api.Event{eventOfType("dns_query"), eventOfType("exec")}) {
		order = append(order, e.rules[i].ID())
	}
	assert.Equal(t, []string{"first", "second", "third"}, order,
		"dispatch must return registration order, and must not repeat a rule that declares two present types")
}

// benchRules builds a catalog of n rules of which exactly one consumes dns_query, modelling the real shape: most rules read exec,
// and the rarely consumed types are read by very few.
func benchRules(n int) []rulesapi.Rule {
	out := make([]rulesapi.Rule, 0, n)
	out = append(out, &typedRule{stubRule: stubRule{id: "dns"}, eventTypes: []string{"dns_query"}})
	for i := 1; i < n; i++ {
		out = append(out, &typedRule{stubRule: stubRule{id: fmt.Sprintf("exec-%d", i)}, eventTypes: []string{"exec"}})
	}
	return out
}

// BenchmarkEvaluate_RareTypeBatch measures the case the index exists for: a batch of a type almost no rule consumes, against a
// catalog large enough that scanning it dominates. Cost should be flat in catalog size.
func BenchmarkEvaluate_RareTypeBatch(b *testing.B) {
	for _, n := range []int{12, 100, 500} {
		b.Run(fmt.Sprintf("catalog=%d", n), func(b *testing.B) {
			e := New(nil, nil)
			e.LoadActive(stubProvider{rules: benchRules(n)})
			batch := []api.Event{eventOfType("dns_query")}
			b.ReportAllocs()
			for b.Loop() {
				_ = e.Evaluate(context.Background(), batch)
			}
		})
	}
}

// BenchmarkEvaluate_MixedBatch measures the unfavourable case: a batch carrying both types, so nearly every rule dispatches and the
// index only adds the union work. This is the cost the optimisation has to be worth paying.
func BenchmarkEvaluate_MixedBatch(b *testing.B) {
	for _, n := range []int{12, 100, 500} {
		b.Run(fmt.Sprintf("catalog=%d", n), func(b *testing.B) {
			e := New(nil, nil)
			e.LoadActive(stubProvider{rules: benchRules(n)})
			batch := []api.Event{eventOfType("exec"), eventOfType("dns_query")}
			b.ReportAllocs()
			for b.Loop() {
				_ = e.Evaluate(context.Background(), batch)
			}
		})
	}
}

// spec:server-detection-rules-engine/a-rule-is-invoked-only-for-batches-carrying-an-event-type-it-consumes/a-triggered-rule-still-sees-the-whole-batch
//
// TestEngine_Evaluate_ADispatchedRuleReceivesTheWholeBatch pins that the declared types are a TRIGGER filter, not a batch filter.
//
// suspicious_exec is the live example: it triggers on a network_connect and then reaches back for the exec that made the connection,
// to name the process in its finding. Handing it only the network_connect events would leave the finding unattributed, so a rule
// that is dispatched sees every event in the batch, including types it never declared.
func TestEngine_Evaluate_ADispatchedRuleReceivesTheWholeBatch(t *testing.T) {
	t.Parallel()

	r := &typedRule{stubRule: stubRule{id: "network-only"}, eventTypes: []string{"network_connect"}}
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{r}})

	batch := []api.Event{eventOfType("exec"), eventOfType("network_connect"), eventOfType("dns_query")}
	require.NoError(t, e.Evaluate(t.Context(), batch))

	require.Equal(t, 1, r.calls, "the batch carries network_connect, so the rule must be invoked")
	assert.Len(t, r.received, 3, "a dispatched rule receives the whole batch, not just its trigger type")
}

// spec:server-detection-rules-engine/a-rule-that-does-not-run-records-no-span/a-rule-scoped-out-by-platform-records-no-span
//
// TestEngine_Evaluate_ASkippedRuleRecordsNoSpan pins that a rule which does not run records nothing.
//
// Both ways of not running are covered: scoped out by platform, and not dispatched at all. A span for either reports evaluation that
// never happened, and at catalog scale it is the bulk of per-rule span volume, since most rules are irrelevant to most batches.
func TestEngine_Evaluate_ASkippedRuleRecordsNoSpan(t *testing.T) {
	t.Parallel()

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	wrongPlatform := &typedRule{
		stubRule:   stubRule{id: "windows-only", platforms: []rulesapi.Platform{rulesapi.PlatformWindows}},
		eventTypes: []string{"exec"},
	}
	notDispatched := &typedRule{stubRule: stubRule{id: "open-only"}, eventTypes: []string{"open"}}
	runs := &typedRule{stubRule: stubRule{id: "exec-rule"}, eventTypes: []string{"exec"}}

	e := New(nil, nil)
	e.tracer = tp.Tracer("server/detection/engine")
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{wrongPlatform, notDispatched, runs}})

	require.NoError(t, e.Evaluate(t.Context(), []api.Event{eventOfType("exec")}))

	var sawRuleIDs []string
	for _, sp := range rec.Ended() {
		for _, a := range sp.Attributes() {
			if a.Key == attribute.Key("rule_id") {
				sawRuleIDs = append(sawRuleIDs, a.Value.AsString())
			}
		}
	}
	assert.Equal(t, []string{"exec-rule"}, sawRuleIDs,
		"only the rule that actually evaluated the batch may record a span")
}

// spec:server-detection-rules-engine/a-rule-is-invoked-only-for-batches-carrying-an-event-type-it-consumes/a-batch-left-with-no-events-evaluates-no-rule
//
// TestEngine_Evaluate_AnEmptyBatchEvaluatesNoRule pins that dispatch did NOT change the empty-batch path.
//
// A rule declaring no event types is selected for every batch, including an empty one, but selection is not evaluation: the
// platform scope leaves nothing, so the rule's Evaluate is never called. That was already true before dispatch existed, because
// evaluateRule has always returned early on an empty scope, and it is asserted here so the fail-open contract is not misread as a
// promise that an unconditional rule runs against nothing.
func TestEngine_Evaluate_AnEmptyBatchEvaluatesNoRule(t *testing.T) {
	t.Parallel()

	undeclared := &stubRule{id: "undeclared"}
	declared := &typedRule{stubRule: stubRule{id: "exec-rule"}, eventTypes: []string{"exec"}}
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{undeclared, declared}})

	require.NoError(t, e.Evaluate(t.Context(), nil))
	assert.Zero(t, undeclared.calls, "an empty batch has nothing to evaluate, so even an unconditional rule is not called")
	assert.Zero(t, declared.calls)

	// And a batch that is entirely plumbing reduces to the same thing.
	require.NoError(t, e.Evaluate(t.Context(), []api.Event{{EventType: "snapshot_heartbeat", Platform: "darwin"}}))
	assert.Zero(t, undeclared.calls)
}

// TestEngine_Evaluate_ARuleDeclaringATypeTwiceIsEvaluatedOnce pins the deduplication in the index build.
//
// It is load-bearing rather than defensive. A single-type batch takes a fast path that returns the index entry verbatim, so a
// duplicate index entry would put the rule in the list twice and evaluate it twice, producing duplicate findings from one batch.
// The general path's sort-and-compact would hide it; the fast path would not.
func TestEngine_Evaluate_ARuleDeclaringATypeTwiceIsEvaluatedOnce(t *testing.T) {
	t.Parallel()

	r := &typedRule{stubRule: stubRule{id: "doubled"}, eventTypes: []string{"exec", "exec"}}
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{r}})

	require.NoError(t, e.Evaluate(t.Context(), []api.Event{eventOfType("exec")}))
	assert.Equal(t, 1, r.calls, "a rule declaring the same event type twice must still be evaluated once per batch")
}

// TestEngine_Evaluate_MixedPlatformBatchDoesNotInvokeARuleOnEventsItCannotSee pins the interaction between dispatch and platform
// scoping.
//
// Dispatch decides on the whole batch, but each rule then sees only the events for its platforms. In a mixed-platform batch those
// differ: a macOS rule reading exec can be selected because a WINDOWS exec is present, and then be handed only the macOS events,
// none of which it consumes. Before this check it was invoked and traced for work it could not do.
//
// The check is skipped when platform scoping leaves the batch intact, which is every batch on a single-platform fleet, so it costs
// nothing until there is something to catch.
func TestEngine_Evaluate_MixedPlatformBatchDoesNotInvokeARuleOnEventsItCannotSee(t *testing.T) {
	t.Parallel()

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	macExec := &typedRule{
		stubRule:   stubRule{id: "mac-exec", platforms: []rulesapi.Platform{rulesapi.PlatformDarwin}},
		eventTypes: []string{"exec"},
	}
	macDNS := &typedRule{
		stubRule:   stubRule{id: "mac-dns", platforms: []rulesapi.Platform{rulesapi.PlatformDarwin}},
		eventTypes: []string{"dns_query"},
	}
	e := New(nil, nil)
	e.tracer = tp.Tracer("server/detection/engine")
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{macExec, macDNS}})

	// The only exec is a Windows one, which no macOS rule can see; the only macOS event is a dns_query.
	require.NoError(t, e.Evaluate(t.Context(), []api.Event{
		{EventType: "exec", Platform: string(rulesapi.PlatformWindows)},
		{EventType: "dns_query", Platform: string(rulesapi.PlatformDarwin)},
	}))

	assert.Zero(t, macExec.calls, "the only exec belongs to a platform this rule cannot see, so it must not be invoked")
	assert.Equal(t, 1, macDNS.calls, "the macOS dns_query is a type this rule declares, so it must be invoked")

	var traced []string
	for _, sp := range rec.Ended() {
		for _, a := range sp.Attributes() {
			if a.Key == attribute.Key("rule_id") {
				traced = append(traced, a.Value.AsString())
			}
		}
	}
	assert.Equal(t, []string{"mac-dns"}, traced, "a rule that was not invoked must record no span")
}

// TestEngine_Evaluate_ManyDistinctEventTypesStayCorrect pins that the set-based path past the scratch array agrees with the linear
// scan it replaces: the same rules are dispatched, once each.
//
// The switch exists because intake validates event_type only as non-empty, so an authenticated host can send a batch whose every
// event carries a distinct junk type. Scanning a slice per event is quadratic in that case.
func TestEngine_Evaluate_ManyDistinctEventTypesStayCorrect(t *testing.T) {
	t.Parallel()

	execRule := &typedRule{stubRule: stubRule{id: "exec-rule"}, eventTypes: []string{"exec"}}
	openRule := &typedRule{stubRule: stubRule{id: "open-rule"}, eventTypes: []string{"open"}}
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{execRule, openRule}})

	// Far past the 16-entry scratch array, with the real type buried among the junk and repeated so duplicates are exercised on
	// the set path too.
	batch := make([]api.Event, 0, 256)
	for i := range 250 {
		batch = append(batch, eventOfType(fmt.Sprintf("junk_type_%d", i)))
	}
	batch = append(batch, eventOfType("exec"), eventOfType("exec"))

	require.NoError(t, e.Evaluate(t.Context(), batch))
	assert.Equal(t, 1, execRule.calls, "the batch carries exec, so the rule runs exactly once despite the duplicate")
	assert.Zero(t, openRule.calls, "no open event is present, so that rule must not run")
}

// BenchmarkEvaluate_ManyDistinctTypes measures the adversarial batch shape: every event a distinct unknown type, dispatching
// nothing. Cost should be linear in batch size, not quadratic.
func BenchmarkEvaluate_ManyDistinctTypes(b *testing.B) {
	for _, n := range []int{100, 500} {
		b.Run(fmt.Sprintf("events=%d", n), func(b *testing.B) {
			e := New(nil, nil)
			e.LoadActive(stubProvider{rules: benchRules(50)})
			batch := make([]api.Event, 0, n)
			for i := range n {
				batch = append(batch, eventOfType(fmt.Sprintf("junk_type_%d", i)))
			}
			b.ReportAllocs()
			for b.Loop() {
				_ = e.Evaluate(context.Background(), batch)
			}
		})
	}
}

// scopedStubRule is a stubRule that also implements rulesapi.ScopedRule, recording which scope it was handed.
type scopedStubRule struct {
	stubRule
	scopes       []*rulesapi.BatchScope
	scopedCalls  int
	derivedValue any
}

func (r *scopedStubRule) EvaluateScoped(
	_ context.Context, scope *rulesapi.BatchScope, events []api.Event, _ rulesapi.GraphReader,
) ([]api.Finding, error) {
	r.scopedCalls++
	r.calls++
	r.received = events
	r.scopes = append(r.scopes, scope)
	// Derive under a shared key, so the test can prove the value crosses rules rather than merely that the pointer does.
	r.derivedValue = scope.Derive("test", func() any { return &struct{ n int }{n: len(events)} })
	return nil, nil
}

// spec:server-detection-rules-engine/rules-evaluating-one-batch-derive-shared-work-once/every-rule-in-one-batch-is-offered-the-same-scope
// spec:server-detection-rules-engine/rules-evaluating-one-batch-derive-shared-work-once/a-later-batch-does-not-see-an-earlier-batch-s-derivations
// spec:server-detection-rules-engine/rules-evaluating-one-batch-derive-shared-work-once/a-rule-that-does-not-use-the-scope-is-unaffected
// TestEngine_ScopedRulesShareOneBatchScope pins the mechanism issue #794 added.
//
// The engine cannot know what a rule derives, so what it guarantees is narrow and exact: every scoped rule in one Evaluate call
// gets the same scope, a different call gets a different one, and a rule that does not implement the interface is untouched. The
// derived value is compared, not just the scope pointer, because sharing a scope that does not actually share values would satisfy
// a pointer check and none of the purpose.
func TestEngine_ScopedRulesShareOneBatchScope(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	first := &scopedStubRule{stubRule: stubRule{id: "scoped-first"}}
	second := &scopedStubRule{stubRule: stubRule{id: "scoped-second"}}
	plain := &stubRule{id: "plain"}
	e.Register(first)
	e.Register(second)
	e.Register(plain)

	events := []api.Event{{EventID: "e1", HostID: "h1", EventType: "exec", Platform: "darwin"}}
	require.NoError(t, e.Evaluate(t.Context(), events))

	require.Len(t, first.scopes, 1)
	require.Len(t, second.scopes, 1)
	assert.Same(t, first.scopes[0], second.scopes[0], "one scope per batch, shared by every scoped rule in it")
	assert.Same(t, first.derivedValue, second.derivedValue, "the second rule reuses what the first derived")

	assert.Equal(t, 1, plain.calls, "a rule that does not implement ScopedRule is still evaluated")
	assert.Equal(t, 0, first.calls-first.scopedCalls, "a scoped rule is evaluated through EvaluateScoped, not Evaluate")

	// A second batch must not see the first batch's derivations: the scope is per call, which is what keeps it out of ADR-0010's
	// cross-request state.
	require.NoError(t, e.Evaluate(t.Context(), events))
	require.Len(t, first.scopes, 2)
	assert.NotSame(t, first.scopes[0], first.scopes[1], "a later batch gets its own scope")
}
