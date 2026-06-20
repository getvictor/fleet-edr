package api_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestBuildNavigatorLayer pins the builder's invariants: the document is always scoped to the macOS platform, the no-rules case
// yields a non-nil empty techniques slice (not null), and per-technique coverage is sorted + deduplicated so the output is
// deterministic. These back the GET /api/attack-coverage contract and the committed docs/attack-navigator-layer.json artifact.
func TestBuildNavigatorLayer(t *testing.T) {
	t.Parallel()

	t.Run("scopes the layer to macOS and pins the enterprise domain", func(t *testing.T) {
		t.Parallel()
		layer := api.BuildNavigatorLayer(nil)
		assert.Equal(t, "enterprise-attack", layer.Domain)
		assert.Equal(t, []string{"macOS"}, layer.Filters.Platforms)
	})

	t.Run("no rules yields a non-nil empty techniques slice", func(t *testing.T) {
		t.Parallel()
		layer := api.BuildNavigatorLayer(nil)
		require.NotNil(t, layer.Techniques, "techniques must serialise as [] not null")
		assert.Empty(t, layer.Techniques)

		// The empty slice must marshal to a JSON array, which the no-rules endpoint contract depends on.
		b, err := json.Marshal(layer)
		require.NoError(t, err)
		assert.Contains(t, string(b), `"techniques":[]`)
	})

	t.Run("sorts techniques and deduplicates covering rule IDs", func(t *testing.T) {
		t.Parallel()
		// Two rules cover T1059 (one of them twice); a third covers T1003. Inputs are out of order so the sort is exercised.
		rules := []api.RuleMetadata{
			{ID: "rule_b", Techniques: []string{"T1059", "T1059"}},
			{ID: "rule_a", Techniques: []string{"T1059"}},
			{ID: "rule_c", Techniques: []string{"T1003"}},
		}
		layer := api.BuildNavigatorLayer(rules)

		require.Len(t, layer.Techniques, 2)
		// Technique IDs are sorted ascending.
		assert.Equal(t, "T1003", layer.Techniques[0].TechniqueID)
		assert.Equal(t, "T1059", layer.Techniques[1].TechniqueID)
		// Covering rule IDs are sorted and the duplicate rule_b is compacted away.
		assert.Equal(t, "Covered by: rule_c", layer.Techniques[0].Comment)
		assert.Equal(t, "Covered by: rule_a, rule_b", layer.Techniques[1].Comment)
		// Every covered technique scores 1.
		assert.Equal(t, 1, layer.Techniques[1].Score)
	})
}

// TestMarshalNavigatorLayerIndented pins the committed-artifact encoding against the literal expected bytes for the deterministic
// no-rules layer: two-space indentation, a trailing newline, the description's ampersand left unescaped (encoding/json's default
// HTML escaping is disabled for the file), and an empty `techniques` array. This is the example-based wire-shape pin; the
// catalog-driven full-document pin lives in the bootstrap drift test against docs/attack-navigator-layer.json.
func TestMarshalNavigatorLayerIndented(t *testing.T) {
	t.Parallel()

	const wantEmptyLayer = `{
  "name": "Fleet EDR coverage",
  "versions": {
    "attack": "19",
    "layer": "4.5",
    "navigator": "5.2.0"
  },
  "domain": "enterprise-attack",
  "description": "MITRE ATT&CK techniques covered by currently-registered Fleet EDR detection rules.",
  "filters": {
    "platforms": [
      "macOS"
    ]
  },
  "techniques": []
}
`

	b, err := api.MarshalNavigatorLayerIndented(api.BuildNavigatorLayer(nil))
	require.NoError(t, err)
	// Literal byte comparison, not assert.JSONEq: this test pins the exact wire bytes (indentation, trailing newline, unescaped
	// ampersand). JSONEq compares JSON semantically and would ignore precisely the formatting this assertion exists to lock.
	//nolint:testifylint // intentional literal-bytes pin; JSONEq would mask the formatting drift this test guards
	assert.Equal(t, wantEmptyLayer, string(b),
		"committed-artifact encoding drifted: indentation, trailing newline, unescaped ampersand, or empty techniques array changed")
}
