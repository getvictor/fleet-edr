package sigma

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// compileYAML parses a `detection:` block from YAML text, which is how a rule actually arrives. Going through YAML rather than a
// hand-built map keeps the tests honest about the types the decoder really produces (map[string]any, []any, int).
func compileYAML(t *testing.T, detection string) (*Rule, error) {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(detection), &doc))
	return Compile(doc)
}

// spec:server-detection-rules-engine/rules-written-in-the-sigma-format-are-evaluated-against-a-single-event/a-rule-matches-an-event-that-satisfies-its-condition
//
// spec:server-detection-rules-engine/rules-written-in-the-sigma-format-are-evaluated-against-a-single-event/a-filter-search-suppresses-a-match
//
// TestCompile_EndToEnd exercises the whole path on rule shapes taken from the macOS corpus: a selection plus a filter set, an
// endswith image match, a contains command-line match, and a list-of-maps search. The rule text is written here rather than
// copied from SigmaHQ, whose content carries the Detection Rule License and whose attribution is issue #765.
func TestCompile_EndToEnd(t *testing.T) {
	t.Parallel()

	const detection = `
selection:
  Image|endswith:
    - '/curl'
    - '/wget'
  CommandLine|contains: 'http'
filter_local:
  CommandLine|contains:
    - '127.0.0.1'
    - 'localhost'
condition: selection and not filter_local
`
	rule, err := compileYAML(t, detection)
	require.NoError(t, err)

	assert.Equal(t, []string{"CommandLine", "Image"}, rule.Fields(), "Fields is sorted and deduplicated across searches")

	cases := []struct {
		name  string
		event mapEvent
		want  bool
	}{
		{"curl to a remote host fires", mapEvent{"Image": {"/usr/bin/curl"}, "CommandLine": {"curl http://evil.example"}}, true},
		{"wget fires too", mapEvent{"Image": {"/usr/bin/wget"}, "CommandLine": {"wget http://evil.example"}}, true},
		{"the loopback filter suppresses", mapEvent{"Image": {"/usr/bin/curl"}, "CommandLine": {"curl http://127.0.0.1:8080"}}, false},
		{"a different binary does not fire", mapEvent{"Image": {"/usr/bin/ssh"}, "CommandLine": {"ssh http://x"}}, false},
		{"the command line must match too", mapEvent{"Image": {"/usr/bin/curl"}, "CommandLine": {"curl --version"}}, false},
		{"a missing field does not fire", mapEvent{"Image": {"/usr/bin/curl"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rule.Matches(tc.event))
		})
	}
}

// TestCompile_ListOfMapsIsDisjunction pins the OR-of-AND shape: a search given as a list matches if ANY entry matches, while the
// fields within one entry must all match. Getting this backwards would turn a broad rule into one that almost never fires.
func TestCompile_ListOfMapsIsDisjunction(t *testing.T) {
	t.Parallel()

	rule, err := compileYAML(t, `
selection:
  - Image|endswith: '/osascript'
    CommandLine|contains: 'do shell script'
  - Image|endswith: '/python3'
    CommandLine|contains: 'urllib'
condition: selection
`)
	require.NoError(t, err)

	assert.True(t, rule.Matches(mapEvent{"Image": {"/usr/bin/osascript"}, "CommandLine": {"osascript -e 'do shell script'"}}),
		"the first alternative matches")
	assert.True(t, rule.Matches(mapEvent{"Image": {"/usr/bin/python3"}, "CommandLine": {"python3 -c 'import urllib'"}}),
		"the second alternative matches")
	assert.False(t, rule.Matches(mapEvent{"Image": {"/usr/bin/osascript"}, "CommandLine": {"python3 -c 'import urllib'"}}),
		"fields are ANDed within one alternative, so a cross-match must not fire")
}

// TestCompile_Rejects covers the structural refusals, all of which would otherwise yield a rule that loads and silently never
// fires.
func TestCompile_Rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		detection string
		want      string
	}{
		{"no condition", "selection:\n  Image: '/bin/sh'\n", "no condition"},
		{"no searches", "condition: selection\n", "defines no searches"},
		{"condition as a list", "selection:\n  Image: '/bin/sh'\ncondition:\n  - selection\n", "must be a single string"},
		{"search is a scalar", "selection: nope\ncondition: selection\n", "must be a field map"},
		{"keyword list search", "selection:\n  - 'some keyword'\ncondition: selection\n", "keyword search is unsupported"},
		{"empty field map", "selection: {}\ncondition: selection\n", "empty field map"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := compileYAML(t, tc.detection)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// spec:server-detection-rules-engine/a-rule-compiles-to-the-same-evaluation-on-every-load/repeated-loads-of-one-rule-resolve-identically
//
// TestCompile_IsDeterministic guards against Go's randomised map iteration reaching the compiled output. A glob quantifier
// resolves against the search names, so an unstable order would make `all of sel_*` evaluate a different set run to run, and the
// resulting flakiness would be blamed on the detection rather than on the loader.
func TestCompile_IsDeterministic(t *testing.T) {
	t.Parallel()

	const detection = `
sel_a:
  Image: '/bin/a'
sel_b:
  Image: '/bin/b'
sel_c:
  Image: '/bin/c'
condition: all of sel_*
`
	first, err := compileYAML(t, detection)
	require.NoError(t, err)
	for range 20 {
		again, err := compileYAML(t, detection)
		require.NoError(t, err)
		require.Len(t, again.searches, len(first.searches))
		for i := range first.searches {
			require.Equal(t, first.searches[i].name, again.searches[i].name, "search order must not vary between loads")
		}
	}
}

// TestRule_FieldsAcrossAlternatives confirms Fields reaches into every alternative of a list-of-maps search, since that is what
// the taxonomy check in #761 will validate against.
func TestRule_FieldsAcrossAlternatives(t *testing.T) {
	t.Parallel()

	rule, err := compileYAML(t, `
selection:
  - Image|endswith: '/osascript'
  - ParentImage|endswith: '/bash'
    TargetFilename|contains: '/tmp/'
condition: selection
`)
	require.NoError(t, err)
	assert.Equal(t, []string{"Image", "ParentImage", "TargetFilename"}, rule.Fields())
}

// spec:server-detection-rules-engine/an-unsupported-or-meaningless-rule-construct-is-refused-when-the-rule-is-loaded/a-reserved-detection-key-is-not-treated-as-a-search
//
// TestCompile_RejectsReservedDetectionKeys pins that a non-search key inside `detection:` is refused rather than compiled as a
// search. `timeframe` belongs to the correlation surface this evaluator does not implement; swept in as a search it would also join
// any `1 of` / `all of` quantifier, so the rule would evaluate a condition nobody wrote.
func TestCompile_RejectsReservedDetectionKeys(t *testing.T) {
	t.Parallel()

	_, err := compileYAML(t, `
selection:
  Image|endswith: '/curl'
timeframe: 15m
condition: selection
`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported Sigma construct")
	assert.Contains(t, err.Error(), "timeframe")
}

// spec:server-detection-rules-engine/an-unsupported-or-meaningless-rule-construct-is-refused-when-the-rule-is-loaded/a-condition-nested-beyond-the-bound-is-refused
//
// TestCompile_RejectsDeeplyNestedConditions pins the recursion bound. Both `not` and parentheses recurse once per level, so without
// a limit a deep enough condition takes the process down inside Compile, whose contract is to return an error.
func TestCompile_RejectsDeeplyNestedConditions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		condition string
	}{
		{"repeated not", strings.Repeat("not ", maxConditionDepth+5) + "selection"},
		{"nested parentheses", strings.Repeat("(", maxConditionDepth+5) + "selection" + strings.Repeat(")", maxConditionDepth+5)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(map[string]any{
				"condition": tc.condition,
				"selection": map[string]any{"Image": "/bin/sh"},
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "nests deeper than")
		})
	}
}

// TestCompile_AcceptsOrdinaryNesting confirms the bound is far above anything real: the corpus nests two or three deep.
func TestCompile_AcceptsOrdinaryNesting(t *testing.T) {
	t.Parallel()

	// Nested to four levels and NOT a tautology: the whole expression reduces to `selection and not filter`.
	r, err := Compile(map[string]any{
		"condition": "not (not (selection and (not filter)))",
		"selection": map[string]any{"Image": "/bin/sh"},
		"filter":    map[string]any{"CommandLine": "safe"},
	})
	require.NoError(t, err)
	assert.True(t, r.Matches(mapEvent{"Image": {"/bin/sh"}}), "selection matches and the filter does not")
	assert.False(t, r.Matches(mapEvent{"Image": {"/bin/sh"}, "CommandLine": {"safe"}}), "the filter suppresses")
	assert.False(t, r.Matches(mapEvent{"Image": {"/bin/zsh"}}), "selection does not match")
}
