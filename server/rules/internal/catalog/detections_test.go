package catalog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
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
			// Deliberately a field no enrichment will ever supply: ParentImage used to serve here and is now supplied
			// (#771), which is exactly the kind of quiet weakening this case exists to prevent.
			"a field the event type does not supply",
			map[string]string{"pack/x.yml": detectionRuleFile("x", "process_creation",
				"  selection:\n    OriginalFileName: 'curl.exe'\n  condition: selection\n")},
			"OriginalFileName",
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

// spec:server-detection-rules-engine/an-alert-from-a-converted-rule-names-what-fired/a-finding-names-the-matched-element-rather-than-the-whole-field
//
// TestFieldReadback covers the helpers a converted rule uses to name what fired. The evaluator reports only THAT a list-valued
// field matched, not which element did, so the rule re-finds it with the same predicate the detection used.
func TestFieldReadback(t *testing.T) {
	t.Parallel()

	payload := `{"pid":1,"ppid":0,"path":"/bin/launchctl","args":["launchctl","load","-w","/Library/LaunchAgents/evil.plist"]}`
	se, err := sigmabind.NewEvent(rulesapi.Event{EventID: "e", EventType: "exec", Payload: []byte(payload)})
	require.NoError(t, err)

	assert.Equal(t, "load", firstField(se, "Subcommand"))
	assert.Equal(t, "/Library/LaunchAgents/evil.plist", firstMatching(se, "CommandArguments", launchAgentPath.MatchString),
		"the element that satisfied the detection, not the first operand")

	assert.Empty(t, firstField(se, "EnvAssignments"), "an absent field reads as empty rather than panicking")
	assert.Empty(t, firstMatching(se, "CommandArguments", func(string) bool { return false }), "no element matches")
	assert.Empty(t, firstMatching(se, "NoSuchField", func(string) bool { return true }))
}

// spec:server-detection-rules-engine/an-alert-from-a-converted-rule-names-what-fired/an-attacker-supplied-value-is-withheld-from-the-description
//
// TestRedactedDyldAssignment pins that the injected library path stays out of the alert. The variable identifies the technique;
// the value is attacker-chosen content that would be rendered into an operator-facing string.
func TestRedactedDyldAssignment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"insert libraries", []string{"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"}, "DYLD_INSERT_LIBRARIES=<redacted>"},
		{"library path", []string{"DYLD_LIBRARY_PATH=/tmp/evil"}, "DYLD_LIBRARY_PATH=<redacted>"},
		{"no assignment", []string{"/usr/bin/true"}, ""},
		{"an unrelated assignment", []string{"PATH=/bin"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload, err := json.Marshal(map[string]any{"pid": 1, "ppid": 0, "path": "/usr/bin/true", "args": tc.argv})
			require.NoError(t, err)
			se, err := sigmabind.NewEvent(rulesapi.Event{EventID: "e", EventType: "exec", Payload: payload})
			require.NoError(t, err)

			got := redactedDyldAssignment(se)
			assert.Equal(t, tc.want, got)
			for _, a := range tc.argv {
				if _, value, found := strings.Cut(a, "="); found && value != "" {
					assert.NotContains(t, got, value, "the assigned value must never reach the description")
				}
			}
		})
	}
}

// spec:server-detection-rules-engine/a-rule-can-match-on-the-parent-process/an-unresolvable-parent-declines-rather-than-matching
//
// TestExecEventWithParent covers what a rule sees for each resolution outcome. The unresolvable case is the one that matters: it is
// the difference between a rule declining and a batch failing.
func TestExecEventWithParent(t *testing.T) {
	t.Parallel()

	evt := rulesapi.Event{EventID: "e", HostID: "h", EventType: "exec", TimestampNs: 100,
		Payload: []byte(`{"pid":1,"ppid":2,"path":"/bin/bash","args":["bash"]}`)}

	cases := []struct {
		name        string
		graph       *recordingGraphReader
		wantValues  []string
		wantPresent bool
	}{
		{
			// The parent is resolved at the CHILD'S fork time, not the event timestamp: a parent must be alive when it forks,
			// but by the exec it may have exited and had its pid reused.
			"a resolved parent supplies the field",
			&recordingGraphReader{byPID: &rulesapi.Process{Path: "/Applications/X", PPID: 2, ForkTimeNs: 50}},
			[]string{"/Applications/X"}, true,
		},
		{
			"an unresolvable child leaves it absent",
			&recordingGraphReader{},
			nil, false,
		},
		{
			// PPID <= 1 means the process was reparented or is a root: there is no meaningful parent image to report.
			"a reparented process has no parent image",
			&recordingGraphReader{byPID: &rulesapi.Process{Path: "/bin/bash", PPID: 1, ForkTimeNs: 50}},
			nil, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			se, err := execEventWithParent(t.Context(), evt, tc.graph, 1)
			require.NoError(t, err)
			values, present := se.Field("ParentImage")
			assert.Equal(t, tc.wantPresent, present)
			assert.Equal(t, tc.wantValues, values)
			require.NoError(t, se.ParentErr(), "an unresolvable parent is a decline, not a failure")
		})
	}
}

// TestExecEventWithParent_ResolvesLazily pins the property that restores the prefilter a converted rule loses.
//
// shell_from_office checked eight shell paths in Go before touching the graph. As a detection block the binary and the parent are
// one condition, so without deferral every exec event on the host would read the process graph. Sigma short-circuits, so a resolver
// is only reached once the cheaper half has already matched.
func TestExecEventWithParent_ResolvesLazily(t *testing.T) {
	t.Parallel()

	evt := rulesapi.Event{EventID: "e", HostID: "h", EventType: "exec", TimestampNs: 100,
		Payload: []byte(`{"pid":1,"ppid":2,"path":"/usr/bin/true","args":["true"]}`)}
	graph := &recordingGraphReader{byPID: &rulesapi.Process{Path: "/Applications/X", PPID: 2, ForkTimeNs: 50}}

	se, err := execEventWithParent(t.Context(), evt, graph, 1)
	require.NoError(t, err)
	assert.False(t, graph.calledByPID, "constructing the adapter must not read the graph")

	// /usr/bin/true is not a shell, so the detection's cheap half fails and the parent is never needed.
	assert.False(t, shellFromOfficeDetection().Matches(se))
	assert.False(t, graph.calledByPID, "a non-matching image must not cost a graph read")

	// Asking for the field directly does resolve it, once.
	values, present := se.Field("ParentImage")
	assert.True(t, present)
	assert.Equal(t, []string{"/Applications/X"}, values)
	assert.True(t, graph.calledByPID)

	graph.calledByPID = false
	se.Field("ParentImage")
	assert.False(t, graph.calledByPID, "the resolver runs at most once per event")
}

// TestExecEventWithParent_ReportsAResolverFailure pins that a graph read failure is distinguishable from a process with no parent.
// Both leave the field absent, and they deserve different handling.
func TestExecEventWithParent_ReportsAResolverFailure(t *testing.T) {
	t.Parallel()

	evt := rulesapi.Event{EventID: "e", HostID: "h", EventType: "exec", TimestampNs: 100,
		Payload: []byte(`{"pid":1,"ppid":2,"path":"/bin/bash","args":["bash"]}`)}
	se, err := execEventWithParent(t.Context(), evt, &recordingGraphReader{errByPID: errors.New("boom")}, 1)
	require.NoError(t, err, "construction does not read the graph, so it cannot fail here")

	_, present := se.Field("ParentImage")
	assert.False(t, present, "a failed lookup leaves the field absent")
	require.Error(t, se.ParentErr(), "and the failure is reported rather than silently read as no parent")
	assert.Contains(t, se.ParentErr().Error(), "get child pid 1")
}
