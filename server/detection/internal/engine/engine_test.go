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

	require.NoError(t, e.Evaluate(t.Context(), nil))

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
