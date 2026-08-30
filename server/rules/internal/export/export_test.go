package export

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/fleetdm/edr/server/rules/api"
)

func metadata() api.RuleMetadata {
	return api.RuleMetadata{
		ID:         "example_rule",
		Techniques: []string{"T1059.004", "T1105"},
		Doc: api.Documentation{
			Title:          "Example rule",
			Summary:        "One-line pitch.",
			Description:    "Long-form behaviour.",
			Severity:       api.SeverityHigh,
			EventTypes:     []string{"exec", "network_connect"},
			FalsePositives: []string{"A benign thing."},
			Limitations:    []string{"A known gap."},
		},
		SupportedExclusionMatchTypes: []api.ExclusionMatchType{api.ExclusionMatchTeamID},
		Platforms:                    []api.Platform{api.PlatformDarwin},
		Algorithm:                    "ancestor_walk_path_prefix",
	}
}

func decode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, yaml.Unmarshal(body, &out))
	return out
}

// spec:server-detection-rules-engine/detections-are-exportable-as-declarative-rule-files/a-detection-exports-as-a-rule-file
//
// TestRule_ShapeAndMapping pins every field the serialiser derives rather than copies. The copied fields are uninteresting; the
// derived ones each encode a decision (Sigma's tag vocabulary, its product name for darwin, one category per rule) that a future
// change could silently get wrong.
func TestRule_ShapeAndMapping(t *testing.T) {
	t.Parallel()

	body, err := Rule(metadata(), Authored{})
	require.NoError(t, err)
	got := decode(t, body)

	assert.Equal(t, "Example rule", got["title"])
	assert.Equal(t, "stable", got["status"])
	assert.Equal(t, "Fleet EDR", got["author"])
	assert.Equal(t, api.SeverityHigh, got["level"])
	assert.Equal(t, []any{"attack.t1059.004", "attack.t1105"}, got["tags"],
		"techniques render in Sigma's tag vocabulary: lowercase, attack-prefixed")
	assert.Equal(t, map[string]any{"product": "macos", "category": "process_creation"}, got["logsource"],
		"darwin is macos in Sigma, and the FIRST event type picks the single allowed category")

	engine, ok := got["x-engine"].(map[string]any)
	require.True(t, ok, "x-engine must be a mapping")
	assert.Equal(t, "example_rule", engine["rule_id"])
	assert.Equal(t, "graph", engine["type"])
	assert.Equal(t, "none", engine["portable"])
	assert.Equal(t, "ancestor_walk_path_prefix", engine["algorithm"])
	assert.Equal(t, []any{"exec", "network_connect"}, engine["event_types"],
		"the full event-type set survives in x-engine even though logsource can carry only one category")
	assert.Equal(t, []any{"team_id"}, engine["exclusions"])
	assert.Equal(t, []any{"A known gap."}, engine["limitations"])
	assert.NotEmpty(t, engine["portability_note"])
}

// TestRule_KeyOrder is the reason this package does not use sigs.k8s.io/yaml like the rest of the tree. That marshaller round-trips
// through JSON and emits keys alphabetically, which puts `author` first and `title` eighth. The pack exists to be read, and every
// Sigma rule an operator has seen opens with title/id/status.
func TestRule_KeyOrder(t *testing.T) {
	t.Parallel()

	body, err := Rule(metadata(), Authored{})
	require.NoError(t, err)

	var order []string
	for line := range strings.SplitSeq(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "#") {
			continue
		}
		if name, _, found := strings.Cut(line, ":"); found {
			order = append(order, name)
		}
	}
	assert.Equal(t,
		[]string{"title", "id", "status", "description", "author", "level", "tags", "logsource", "falsepositives", "x-engine"},
		order)
}

// TestRuleID_IsStableAndDistinct guards the derivation itself. The id is a uuid5 precisely so everyone computes the same answer,
// so a changed namespace or input silently renumbers every rule in the catalog, and downstream tools key on that number.
func TestRuleID_IsStableAndDistinct(t *testing.T) {
	t.Parallel()

	// Pinned literals, not a recomputation: recomputing the derivation with the same code under test would pass even if the
	// namespace changed, which is the exact regression worth catching.
	assert.Equal(t, "77a66007-aa88-5521-9471-50a20231e8c6", RuleID("credential_keychain_dump"))
	assert.Equal(t, "84a2309d-9c77-54c8-8b29-e7d484e890dd", RuleID("suspicious_exec"))
	assert.NotEqual(t, RuleID("a"), RuleID("b"), "distinct rule ids must not collide")
}

// TestRule_DescriptionJoin covers the one place two source fields collapse into one Sigma field. Sigma has no summary, and either
// half alone loses something an operator reads.
func TestRule_DescriptionJoin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		summary     string
		description string
		want        string
	}{
		{"both", "Pitch.", "Detail.", "Pitch.\n\nDetail."},
		{"summary only", "Pitch.", "", "Pitch."},
		{"description only", "", "Detail.", "Detail."},
		{"neither", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, description(api.Documentation{Summary: tc.summary, Description: tc.description}))
		})
	}
}

// TestRule_UnmappedEventTypeKeepsItsOwnName pins the deliberate non-invention. A Background Task Management registration has no
// Sigma category, and inventing a plausible one would misrepresent the file to any tool that read it.
func TestRule_UnmappedEventTypeKeepsItsOwnName(t *testing.T) {
	t.Parallel()

	md := metadata()
	md.Doc.EventTypes = []string{"btm_launch_item_add"}
	body, err := Rule(md, Authored{})
	require.NoError(t, err)

	logsource, ok := decode(t, body)["logsource"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "btm_launch_item_add", logsource["category"])
}

// TestRule_OmitsEmptyOptionalKeys asserts a rule with no false positives, limitations or exclusions emits no key for them rather
// than an empty list. An empty `exclusions: []` implies a tuning surface the rule does not have.
func TestRule_OmitsEmptyOptionalKeys(t *testing.T) {
	t.Parallel()

	md := metadata()
	md.Doc.FalsePositives = nil
	md.Doc.Limitations = nil
	md.SupportedExclusionMatchTypes = nil
	md.Techniques = nil
	body, err := Rule(md, Authored{})
	require.NoError(t, err)

	got := decode(t, body)
	assert.NotContains(t, got, "falsepositives")
	assert.NotContains(t, got, "tags")
	engine, ok := got["x-engine"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, engine, "exclusions")
	assert.NotContains(t, engine, "limitations")
}

// spec:server-detection-rules-engine/detections-are-exportable-as-declarative-rule-files/incomplete-metadata-is-refused-rather-than-half-rendered
//
// TestRule_RejectsUnrenderableMetadata covers the refusal paths. A file silently missing its logsource or level looks
// authoritative and is not, so the serialiser errors rather than emitting a partial document.
func TestRule_RejectsUnrenderableMetadata(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		mut  func(*api.RuleMetadata)
		want string
	}{
		{"no id", func(m *api.RuleMetadata) { m.ID = "" }, "no id"},
		{"no platform", func(m *api.RuleMetadata) { m.Platforms = nil }, "declares no platform"},
		{"no event types", func(m *api.RuleMetadata) { m.Doc.EventTypes = nil }, "declares no event types"},
		{"unknown platform", func(m *api.RuleMetadata) { m.Platforms = []api.Platform{"plan9"} }, "unknown platform"},
		{"no title", func(m *api.RuleMetadata) { m.Doc.Title = "" }, "has no title"},
		{"no severity", func(m *api.RuleMetadata) { m.Doc.Severity = "" }, "has no severity"},
		// The most dangerous omission of the three: omitempty DROPS an empty algorithm rather than emitting a blank one, so the
		// file would look complete while missing the single thing that says what decides the rule.
		{"no algorithm and no detection", func(m *api.RuleMetadata) { m.Algorithm = "" }, "names no algorithm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			md := metadata()
			tc.mut(&md)
			_, err := Rule(md, Authored{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestPack_AllOrNothing pins that one unrenderable rule fails the whole pack. Half a pack looks like a real one to the next
// reader and to CI's drift check; an error with nothing written does not.
func TestPack_AllOrNothing(t *testing.T) {
	t.Parallel()

	good := metadata()
	bad := metadata()
	bad.ID = "broken_rule"
	bad.Platforms = nil

	pack, err := Pack([]api.RuleMetadata{good, bad}, func(string) Authored { return Authored{} })
	require.Error(t, err)
	assert.Nil(t, pack)
	assert.Contains(t, err.Error(), "broken_rule")

	pack, err = Pack([]api.RuleMetadata{good}, func(string) Authored { return Authored{} })
	require.NoError(t, err)
	assert.Len(t, pack, 1)
	assert.Contains(t, pack, "example_rule")
}

// TestFile_IsTheDocumentBehindTheHeader pins the difference between the two surfaces. The committed pack carries a
// generated-file header; the document served over HTTP does not, because telling an operator not to hand-edit their own download
// would be both wrong and confusing.
func TestFile_IsTheDocumentBehindTheHeader(t *testing.T) {
	t.Parallel()

	md := metadata()
	doc, err := Rule(md, Authored{})
	require.NoError(t, err)
	f, err := File(md, Authored{})
	require.NoError(t, err)

	assert.Equal(t, Header+string(doc), string(f))
	assert.True(t, strings.HasPrefix(string(f), "# Generated by"))
	assert.False(t, strings.HasPrefix(string(doc), "#"), "the served document opens with YAML, not a comment")
}

// TestPack_RendersCommittedFileBytes confirms Pack yields what the generator writes to disk, header included, so the drift check
// compares like with like rather than re-deriving the header at the comparison site.
func TestPack_RendersCommittedFileBytes(t *testing.T) {
	t.Parallel()

	pack, err := Pack([]api.RuleMetadata{metadata()}, func(string) Authored { return Authored{} })
	require.NoError(t, err)
	require.Contains(t, pack, "example_rule")
	assert.True(t, strings.HasPrefix(string(pack["example_rule"]), Header))
}

// TestRule_EmitsParamsVerbatim pins that a params block is re-emitted exactly as authored, comments included. Params are the one
// part of a rule file the rules READ, so they are the source of truth rather than generated output; re-rendering them from parsed
// values would drop the comments explaining why each threshold is what it is, which is the most valuable content in the block.
func TestRule_EmitsParamsVerbatim(t *testing.T) {
	t.Parallel()

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("window: 30s\n# why this value\nshells:\n  - /bin/sh\n"), &node))
	require.NotEmpty(t, node.Content)

	body, err := Rule(metadata(), Authored{Params: node.Content[0]})
	require.NoError(t, err)
	assert.Contains(t, string(body), "window: 30s")
	assert.Contains(t, string(body), "# why this value")
	assert.Contains(t, string(body), "- /bin/sh")
}

// TestRule_OmitsAnAbsentParamsBlock keeps a rule with nothing to tune from carrying an empty key that implies otherwise.
func TestRule_OmitsAnAbsentParamsBlock(t *testing.T) {
	t.Parallel()

	body, err := Rule(metadata(), Authored{})
	require.NoError(t, err)
	assert.NotContains(t, string(body), "params:")
}

// detectionNode parses a detection block into the node Rule re-emits.
func detectionNode(t *testing.T, body string) *yaml.Node {
	t.Helper()
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(body), &n))
	require.NotEmpty(t, n.Content)
	return n.Content[0]
}

// spec:server-detection-rules-engine/portability-is-derived-from-the-rule-rather-than-declared/portability-is-derived-from-the-rule-rather-than-declared
//
// TestClassify derives type and portability from the rule itself. Getting this wrong is not cosmetic: `portable` is the field that
// tells another team whether they can run our rule, so a wrong answer is a promise we do not keep.
func TestClassify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		detection    string
		wantKind     string
		wantPortable string
	}{
		{"no detection block is a Go implementation", "", "graph", "none"},
		{
			"only Sigma's own fields is standard",
			"selection:\n  Image|endswith: '/curl'\n  CommandLine|contains: 'http'\ncondition: selection\n",
			"sigma", "standard",
		},
		{
			"a computed field makes it mapped",
			"selection:\n  Subcommand|re: '^dump-keychain$'\ncondition: selection\n",
			"sigma", "mapped",
		},
		{
			"one computed field among standard ones is enough",
			"selection:\n  Image: '/usr/bin/security'\n  Subcommand: 'dump-keychain'\ncondition: selection\n",
			"sigma", "mapped",
		},
		{
			"a computed field inside a list-of-maps search still counts",
			"selection:\n  - Image: '/a'\n  - EnvAssignments|re: '^DYLD_'\ncondition: selection\n",
			"sigma", "mapped",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var node *yaml.Node
			if tc.detection != "" {
				node = detectionNode(t, tc.detection)
			}
			kind, portable := classify(node)
			assert.Equal(t, tc.wantKind, kind)
			assert.Equal(t, tc.wantPortable, portable)
		})
	}
}

// TestIsComputedField pins the set that decides standard from mapped. server/rules/internal/sigmabind drift-tests its taxonomy
// against this, so the two cannot disagree about which fields another engine would be missing.
func TestIsComputedField(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"Subcommand", "CommandArguments", "EnvAssignments"} {
		assert.True(t, IsComputedField(name), "%s is computed by this engine", name)
	}
	for _, name := range []string{"Image", "CommandLine", "TargetFilename", "ParentImage"} {
		assert.False(t, IsComputedField(name), "%s comes from Sigma's own taxonomy", name)
	}
}

// TestRule_EmitsDetectionAndDropsTheAlgorithm covers what a converted rule's file looks like: its logic is present, and the Go
// evaluator it no longer uses is not.
func TestRule_EmitsDetectionAndDropsTheAlgorithm(t *testing.T) {
	t.Parallel()

	body, err := Rule(metadata(), Authored{
		Detection: detectionNode(t, "selection:\n  Subcommand|re: '^dump-keychain$'\ncondition: selection\n"),
	})
	require.NoError(t, err)

	got := decode(t, body)
	require.Contains(t, got, "detection")
	engine, ok := got["x-engine"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "sigma", engine["type"])
	assert.Equal(t, "mapped", engine["portable"])
	assert.NotContains(t, engine, "algorithm",
		"a converted rule's logic IS its detection block; naming a Go evaluator beside it points the reader at dead code")
	assert.Contains(t, engine["portability_note"], "detection block in this file")
}

// TestRule_DetectionSitsWhereSigmaReadersExpectIt pins the position, since a rule file is read by people and by other tools that
// have seen thousands of Sigma rules with detection between logsource and falsepositives.
func TestRule_DetectionSitsWhereSigmaReadersExpectIt(t *testing.T) {
	t.Parallel()

	body, err := Rule(metadata(), Authored{
		Detection: detectionNode(t, "selection:\n  Image: '/x'\ncondition: selection\n"),
	})
	require.NoError(t, err)

	var order []string
	for line := range strings.SplitSeq(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "#") {
			continue
		}
		if name, _, found := strings.Cut(line, ":"); found {
			order = append(order, name)
		}
	}
	assert.Equal(t,
		[]string{"title", "id", "status", "description", "author", "level", "tags", "logsource", "detection", "falsepositives", "x-engine"},
		order)
}

// TestRule_GraphRuleStillNeedsAnAlgorithm pins that dropping the algorithm is allowed only because a detection block took over. A
// rule with neither would export a file that cannot say what decides it.
func TestRule_GraphRuleStillNeedsAnAlgorithm(t *testing.T) {
	t.Parallel()

	md := metadata()
	md.Algorithm = ""
	_, err := Rule(md, Authored{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "names no algorithm and has no detection block")

	_, err = Rule(md, Authored{Detection: detectionNode(t, "selection:\n  Image: '/x'\ncondition: selection\n")})
	require.NoError(t, err, "a detection block is the other way a rule says what decides it")
}
