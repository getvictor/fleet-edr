package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

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
func (r *stubRule) Techniques() []string { return r.techniques }
func (r *stubRule) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{
		Title:    "Stub",
		Severity: rulesapi.SeverityHigh,
	}
}
func (r *stubRule) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	return nil, nil
}

func TestEngine_RegisterAccumulates(t *testing.T) {
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
