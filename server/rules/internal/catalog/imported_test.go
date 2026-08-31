package catalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/a-rule-this-sensor-cannot-run-is-refused-by-name/a-rule-reading-an-unavailable-field-is-refused-and-the-others-still-import
//
// TestLoadImported_UpstreamRulesLoadUnmodified is the acceptance criterion of issue #763 stated literally: a SigmaHQ file imports
// byte-identical, with no `x-engine` block and nothing added.
//
// The fixtures under testdata/imported are verbatim copies of SigmaHQ macOS rules. Nothing about them was edited to make this pass,
// which is the whole claim: every key we made mandatory would be a key that forks the corpus and turns a re-sync into a merge
// conflict.
func TestLoadImported_UpstreamRulesLoadUnmodified(t *testing.T) {
	t.Parallel()

	rules, rejected, err := loadImported(os.DirFS("testdata"), "imported")
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	// The corpus genuinely contains one rule this sensor cannot run, and it is reported rather than dropped. Asserting the exact
	// set keeps a future fixture that stops importing from passing unnoticed.
	require.Len(t, rejected, 1)
	assert.Contains(t, rejected[0].File, "meshagent")
	assert.Contains(t, rejected[0].Reason, "OriginalFileName",
		"the reason must name the field, so an operator knows why the rule is absent")

	byID := make(map[string]api.Rule, len(rules))
	for _, r := range rules {
		byID[r.ID()] = r
	}

	// A process_creation rule and a file_event rule, so both category mappings are exercised by real upstream files.
	t.Run("a process_creation rule", func(t *testing.T) {
		t.Parallel()
		r := byID["proc_creation_macos_applescript"]
		require.NotNil(t, r, "the rule id defaults to the filename stem")
		assert.NotEmpty(t, r.DisplayName())
		assert.Equal(t, []api.Platform{api.PlatformDarwin}, r.Platforms())
		assert.Equal(t, []string{"exec"}, r.Doc().EventTypes, "process_creation maps to exec")
		assert.NotEmpty(t, r.Doc().Severity)
	})

	t.Run("a file_event rule", func(t *testing.T) {
		t.Parallel()
		r := byID["file_event_macos_emond_launch_daemon"]
		require.NotNil(t, r)
		assert.Equal(t, []string{"open"}, r.Doc().EventTypes, "file_event maps to open")
		assert.Equal(t, api.SeverityMedium, r.Doc().Severity, "level: medium")
		assert.Equal(t, []string{"T1546.014"}, r.Techniques(), "only the technique tag, not the tactic tags")
		assert.Equal(t, []string{"Legitimate administration activities"}, r.Doc().FalsePositives)
	})

	t.Run("every imported rule satisfies the engine's contract", func(t *testing.T) {
		t.Parallel()
		for _, r := range rules {
			assert.NotEmpty(t, r.ID(), "an id is what an alert and an exclusion key on")
			assert.NotEmpty(t, r.DisplayName(), "a rule with no name cannot be triaged")
			assert.NotEmpty(t, r.Platforms(), "the engine scopes every batch by platform")
			assert.NotEmpty(t, r.Doc().EventTypes, "the engine dispatches on this (#762)")
			assert.NotEmpty(t, r.Doc().Severity)
		}
	})
}

// TestParseImported_RefusesWhatItCannotRun pins that an unimportable file fails the load with a reason naming what is wrong.
//
// Skipping would be worse than failing. A skipped rule is indistinguishable from a rule that never matches, and the whole point of
// importing a detection corpus is that the detections run.
func TestParseImported_RefusesWhatItCannotRun(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		file    string
		wantErr string
	}{
		{
			name: "a field this engine does not supply",
			file: `title: T
level: medium
logsource: {category: process_creation, product: macos}
detection: {sel: {OriginalFileName: x}, condition: sel}`,
			wantErr: "OriginalFileName",
		},
		{
			name: "a category that maps to no event we collect",
			file: `title: T
level: medium
logsource: {category: registry_set, product: windows}
detection: {sel: {Image: x}, condition: sel}`,
			wantErr: "registry_set",
		},
		{
			name: "a product that is not a platform we target",
			file: `title: T
level: medium
logsource: {category: process_creation, product: aix}
detection: {sel: {Image: x}, condition: sel}`,
			wantErr: "aix",
		},
		{
			name: "a level we cannot raise an alert at",
			file: `title: T
level: catastrophic
logsource: {category: process_creation, product: macos}
detection: {sel: {Image: x}, condition: sel}`,
			wantErr: "catastrophic",
		},
		{
			name: "no detection block at all",
			file: `title: T
level: medium
logsource: {category: process_creation, product: macos}`,
			wantErr: "no detection block",
		},
		{
			name: "no title",
			file: `level: medium
logsource: {category: process_creation, product: macos}
detection: {sel: {Image: x}, condition: sel}`,
			wantErr: "no title",
		},
		{
			name: "a condition naming a search that does not exist",
			file: `title: T
level: medium
logsource: {category: process_creation, product: macos}
detection: {sel: {Image: x}, condition: other}`,
			wantErr: "other",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseImported("rule.yml", []byte(tc.file))
			require.Error(t, err, "must be refused rather than imported broken")
			assert.Contains(t, err.Error(), tc.wantErr, "the message must name what is wrong")
		})
	}
}

// spec:server-detection-rules-engine/a-rule-this-sensor-cannot-run-is-refused-by-name/two-files-claiming-one-identifier-fail-the-import
//
// TestLoadImported_RefusesADuplicateRuleID pins that two files resolving to one id fail the import rather than one quietly
// replacing the other.
//
// This is reachable because the import walks a TREE: an upstream corpus is laid out as rules/<product>/<category>/, so two
// categories can each hold a file of the same name, and the id is the filename stem. Whichever loaded second would otherwise
// silently win, and the rule an operator sees would depend on directory order.
func TestLoadImported_RefusesADuplicateRuleID(t *testing.T) {
	t.Parallel()

	body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\ndetection: {sel: {Image: x}, condition: sel}\n")
	dir := t.TempDir()
	for _, sub := range []string{"process_creation", "file_event"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, sub, "same_name.yml"), body, 0o600))
	}

	_, _, err := loadImported(os.DirFS(dir), ".")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same_name", "the message must name the id that collided")
	assert.Contains(t, err.Error(), "already imported from", "and where it was first seen")
}

// TestLoadImported_WalksTheTree pins that a nested corpus imports, which is how upstream is laid out.
func TestLoadImported_WalksTheTree(t *testing.T) {
	t.Parallel()

	body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\ndetection: {sel: {Image: x}, condition: sel}\n")
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "macos", "process_creation"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "macos", "process_creation", "nested.yml"), body, 0o600))

	rules, rejected, err := loadImported(os.DirFS(dir), ".")
	require.NoError(t, err)
	assert.Empty(t, rejected)
	require.Len(t, rules, 1)
	assert.Equal(t, "nested", rules[0].ID(), "the id is the stem, whatever directory the file sits in")
}

// TestTechniquesFrom pins the tag mapping, which decides what an imported rule reports to ATT&CK navigator export.
func TestTechniquesFrom(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		tags []string
		want []string
	}{
		{"a technique with a sub-technique", []string{"attack.t1546.014"}, []string{"T1546.014"}},
		{"a bare technique", []string{"attack.t1059"}, []string{"T1059"}},
		{"tactics carry no technique", []string{"attack.persistence", "attack.privilege-escalation"}, []string{}},
		{"mixed tags keep only the techniques", []string{"attack.persistence", "attack.t1546.014"}, []string{"T1546.014"}},
		{"a non-attack tag is ignored", []string{"cve.2021-1234", "detection.threat-hunting"}, []string{}},
		{"a malformed technique tag is ignored", []string{"attack.tsomething"}, []string{}},
		{"a trailing dot is not a technique", []string{"attack.t1059."}, []string{}},
		{"no tags at all", nil, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, techniquesFrom(tc.tags))
		})
	}
}

// spec:server-detection-rules-engine/a-detection-can-be-an-upstream-sigma-file-with-nothing-added/an-unmodified-upstream-rule-loads-and-fires
//
// TestImportedRule_FiresOnAMatchingEvent is the other half of issue #763's acceptance criterion: an upstream rule imports
// byte-identical AND fires correctly.
//
// The rule is a verbatim SigmaHQ file (`proc_creation_macos_chflags_hidden_flag.yml`), matching on `Image|endswith: '/chflags'`
// and `CommandLine|contains: 'hidden '`. Nothing in it was written for this engine, which is the point: the taxonomy carries it.
func TestImportedRule_FiresOnAMatchingEvent(t *testing.T) {
	t.Parallel()

	rules, _, err := loadImported(os.DirFS("testdata"), "imported")
	require.NoError(t, err)
	var rule api.Rule
	for _, r := range rules {
		if r.ID() == "proc_creation_macos_chflags_hidden_flag" {
			rule = r
		}
	}
	require.NotNil(t, rule)

	ctx := t.Context()
	store := openCatalogStore(t)
	exec := api.Event{
		EventID: "e1", HostID: "h1", EventType: "exec", TimestampNs: 2,
		Payload: []byte(`{"pid":4242,"ppid":1,"path":"/usr/bin/chflags","args":["chflags","hidden","/tmp/payload"]}`),
	}
	require.NoError(t, store.InsertEvents(ctx, []detectionapi.Event{exec}))
	require.NoError(t, store.ProcessBatch(ctx, []detectionapi.Event{exec}))

	findings, err := rule.Evaluate(ctx, []api.Event{exec}, store.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "the upstream rule must fire on the behaviour it describes")

	got := findings[0]
	assert.Equal(t, "proc_creation_macos_chflags_hidden_flag", got.RuleID)
	assert.Equal(t, api.SeverityMedium, got.Severity, "the alert carries the severity the upstream level maps to")
	assert.Equal(t, rule.DisplayName(), got.Title)
	assert.NotZero(t, got.ProcessID, "the finding links to the process that ran it")

	t.Run("and not on an event it does not describe", func(t *testing.T) {
		t.Parallel()
		other := api.Event{
			EventID: "e2", HostID: "h1", EventType: "exec", TimestampNs: 3,
			Payload: []byte(`{"pid":4243,"ppid":1,"path":"/usr/bin/chflags","args":["chflags","nouchg","/tmp/x"]}`),
		}
		findings, err := rule.Evaluate(ctx, []api.Event{other}, store.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "chflags without the hidden flag is not what the rule describes")
	})
}
