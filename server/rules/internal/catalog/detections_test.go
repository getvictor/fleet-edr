package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detectionFile builds a minimal pack file carrying a detection block.
func detectionRuleFile(ruleID, category, detection string) string {
	return "title: T\nlogsource:\n  category: " + category + "\ndetection:\n" + detection +
		"x-engine:\n  rule_id: " + ruleID + "\n"
}

// spec:server-detection-rules-engine/a-converted-rule-carries-its-logic-in-its-file/a-detection-block-is-compiled-and-checked-when-the-pack-loads
//
// TestLoadDetections_CompilesAndChecks covers the happy path: a detection block compiles and every field it reads is one the event
// type supplies.
func TestLoadDetections_CompilesAndChecks(t *testing.T) {
	t.Parallel()

	got, err := loadDetections(fsWith(map[string]string{
		"pack/x.yml": detectionRuleFile("x", "process_creation",
			"  selection:\n    Image|endswith: '/security'\n  condition: selection\n"),
	}))
	require.NoError(t, err)
	require.Contains(t, got, "x")
	// Bound before dereferencing: require.Contains is not a guard nilaway recognises on a map read.
	d := got["x"]
	require.NotNil(t, d)
	assert.NotNil(t, d.rule)
	assert.NotNil(t, d.raw, "the verbatim node is kept so regeneration re-emits it")
}

// TestLoadDetections_SkipsGraphRules pins that a rule without a detection block is not an error: it is the other half of the
// catalog, and it declares its logic by naming a Go evaluator instead.
func TestLoadDetections_SkipsGraphRules(t *testing.T) {
	t.Parallel()

	got, err := loadDetections(fsWith(map[string]string{
		"pack/graph.yml": "title: T\nx-engine:\n  rule_id: graph\n  algorithm: some_walk\n",
	}))
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestLoadDetections_Rejects covers the refusals. Each would otherwise produce a rule that loads and then never matches, which is
// indistinguishable from the behaviour never occurring.
func TestLoadDetections_Rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			"a detection that does not compile",
			map[string]string{"pack/x.yml": detectionRuleFile("x", "process_creation",
				"  selection:\n    Image: '/x'\n  condition: nosuchsearch\n")},
			"undefined search",
		},
		{
			"a field the event type does not supply",
			map[string]string{"pack/x.yml": detectionRuleFile("x", "process_creation",
				"  selection:\n    ParentImage: '/bin/bash'\n  condition: selection\n")},
			"ParentImage",
		},
		{
			// A detection under a category we cannot populate would pass a logsource check and then match nothing forever.
			"a logsource category we supply no fields for",
			map[string]string{"pack/x.yml": detectionRuleFile("x", "dns_query",
				"  selection:\n    Image: '/x'\n  condition: selection\n")},
			"no event type we supply fields for",
		},
		{
			"a detection block that is not a mapping",
			map[string]string{"pack/x.yml": "title: T\nlogsource:\n  category: process_creation\ndetection: junk\n" +
				"x-engine:\n  rule_id: x\n"},
			"not a mapping",
		},
		{
			"a file with a detection but no rule id",
			map[string]string{"pack/x.yml": "title: T\nlogsource:\n  category: process_creation\n" +
				"detection:\n  selection:\n    Image: '/x'\n  condition: selection\n"},
			"rule_id is empty",
		},
		{
			// The registry guard checks the same invariant from the Go side; this closes it on the file, which a hand edit
			// reaches without touching Go at all.
			"a file declaring both a detection block and an algorithm",
			map[string]string{"pack/x.yml": "title: T\nlogsource:\n  category: process_creation\n" +
				"detection:\n  selection:\n    Image: '/x'\n  condition: selection\n" +
				"x-engine:\n  rule_id: x\n  algorithm: some_walk\n"},
			"only one can decide it",
		},
		{
			"a rule id repeated across files",
			map[string]string{
				"pack/a.yml": detectionRuleFile("dup", "process_creation", "  selection:\n    Image: '/a'\n  condition: selection\n"),
				"pack/b.yml": detectionRuleFile("dup", "process_creation", "  selection:\n    Image: '/b'\n  condition: selection\n"),
			},
			"duplicate rule_id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadDetections(fsWith(tc.files))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestDetectionFor_PanicsForAGraphRule pins that asking a graph rule for a detection is a programming error rather than a silent
// non-match. A rule that reached evaluation with no logic would detect nothing for as long as it stayed installed.
func TestDetectionFor_PanicsForAGraphRule(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t,
		`catalog: rule "suspicious_exec" has no detection block; a converted rule's logic lives in its pack file`,
		func() { detectionFor("suspicious_exec") })
}

// TestAuthoredFor covers what regeneration re-emits: a converted rule supplies its detection block, a graph rule supplies only its
// params, and neither loses what it has.
func TestAuthoredFor(t *testing.T) {
	t.Parallel()

	converted := AuthoredFor("credential_keychain_dump")
	assert.NotNil(t, converted.Detection, "a converted rule's logic must survive regeneration")
	assert.Nil(t, converted.Params, "its match values moved into the detection block")

	graph := AuthoredFor("suspicious_exec")
	assert.Nil(t, graph.Detection)
	assert.NotNil(t, graph.Params, "a graph rule still reads its values from params")
}

// TestMustLoadDetections_LoadsTheEmbeddedPack pins the eager path, which is what makes a malformed block fail when the catalog is
// built rather than on the first detection.
func TestMustLoadDetections_LoadsTheEmbeddedPack(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, MustLoadDetections)
}
