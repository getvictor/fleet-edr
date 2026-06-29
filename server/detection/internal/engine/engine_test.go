package engine

import (
	"context"
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
func (r *stubRule) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	return nil, nil
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

	// Override ONLY the package-level tracer var (no otel.SetTracerProvider call) so go test's package-parallel scheduler can't race
	// this with another package's instrumentation. Restore on cleanup so the next test in this package sees the production tracer.
	prevTracer := tracer
	tracer = tp.Tracer("server/detection/engine")
	t.Cleanup(func() { tracer = prevTracer })

	e := New(nil, nil)
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
