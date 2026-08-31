package catalog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// spec:server-detection-rules-engine/a-rule-this-sensor-cannot-run-is-refused-by-name/a-rule-reading-an-unavailable-field-is-refused-and-the-others-still-import
//
// TestLoadImported_TheWholeUpstreamCorpus is issue #763's acceptance criterion stated as a test rather than as a number in a PR
// description: the ENTIRE SigmaHQ macOS corpus imports, unmodified, and the one rule this sensor cannot run is refused by name.
//
// The fixtures are the upstream tree copied byte-for-byte, including its `<category>/` layout, so this exercises the directory walk
// the production loader does. Asserting the exact counts rather than a lower bound is the point: a version that imported one rule
// and rejected 68 would satisfy "some rules import", and that is precisely the regression worth catching.
func TestLoadImported_TheWholeUpstreamCorpus(t *testing.T) {
	t.Parallel()

	rules, rejected, err := loadImported(os.DirFS("testdata"), "imported")
	require.NoError(t, err)

	assert.Len(t, rules, 66, "the rest read only fields this sensor supplies, in a category it collects broadly enough")

	// Two refusals, for two different reasons, and both are the refusal contract working rather than a gap.
	reasons := map[string]string{}
	for _, r := range rejected {
		reasons[path.Base(r.File)] = r.Reason
		assert.NotContains(t, r.Reason, r.File, "the reason does not repeat the file, which the rejection already carries")
	}
	require.Len(t, rejected, 3, "one unsupplied field, and two rules in a category this agent collects too narrowly")

	assert.Contains(t, reasons["proc_creation_macos_remote_access_tools_renamed_meshagent_execution.yml"], "OriginalFileName",
		"a field this sensor does not collect, named so an operator knows why the rule is absent")
	for _, f := range []string{"file_event_macos_emond_launch_daemon.yml", "file_event_macos_susp_startup_item_created.yml"} {
		assert.Contains(t, reasons[f], "/etc/sudoers",
			"a file_event rule cannot fire on this agent, and the reason says which telemetry is missing")
	}

	byID := make(map[string]api.Rule, len(rules))
	for _, r := range rules {
		byID[r.ID()] = r
	}

	t.Run("a process_creation rule", func(t *testing.T) {
		t.Parallel()
		r := byID["proc_creation_macos_applescript"]
		require.NotNil(t, r, "the rule id defaults to the filename stem")
		assert.NotEmpty(t, r.DisplayName())
		assert.Equal(t, []api.Platform{api.PlatformDarwin}, r.Platforms())
		assert.Equal(t, []string{"exec"}, r.Doc().EventTypes, "process_creation maps to exec")
	})

	t.Run("a file_event rule is not imported", func(t *testing.T) {
		t.Parallel()
		assert.NotContains(t, byID, "file_event_macos_emond_launch_daemon",
			"it watches /etc/emond.d, which this agent emits no open event for, so importing it would be coverage we do not have")
	})

	t.Run("metadata comes from the file", func(t *testing.T) {
		t.Parallel()
		// Required rather than skipped: a subtest that skips when its fixture is missing asserts nothing, and an earlier version
		// of this one named a rule the corpus does not contain and passed for months of nobody noticing.
		r := byID["proc_creation_macos_xattr_gatekeeper_bypass"]
		require.NotNil(t, r, "fixture renamed upstream: point this at a rule that exists rather than letting it skip")
		assert.NotEmpty(t, r.Doc().Description, "the description is the upstream one")
		assert.NotEmpty(t, r.Doc().Severity)
		assert.Equal(t, []api.Platform{api.PlatformDarwin}, r.Platforms())
	})

	t.Run("every imported rule satisfies the engine's contract", func(t *testing.T) {
		t.Parallel()
		for _, r := range rules {
			assert.NotEmpty(t, r.ID(), "an id is what an alert and an exclusion key on")
			assert.NotEmpty(t, r.DisplayName(), "a rule with no name cannot be triaged")
			assert.NotEmpty(t, r.Platforms(), "the engine scopes every batch by platform")
			assert.NotEmpty(t, r.Doc().EventTypes, "the engine dispatches on this (#762)")
			assert.NotEmpty(t, r.Doc().Severity, "an alert has to be raised at some severity")
		}
	})
}

// TestSeverityFor pins every level mapping, because the severity an alert carries is behaviour this PR introduces and the corpus
// test above only asserts that one is present.
func TestSeverityFor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		level         string
		want          string
		wantErr       string
		wantRejection bool
	}{
		{level: "critical", want: api.SeverityCritical},
		{level: "high", want: api.SeverityHigh},
		{level: "medium", want: api.SeverityMedium},
		{level: "low", want: api.SeverityLow},
		// 7 of the 69 macOS rules are informational. It has no counterpart here, and refusing them would fork the corpus over a
		// label, so it lands at the lowest severity we can raise.
		{level: "informational", want: api.SeverityLow},
		{level: "MEDIUM", want: api.SeverityMedium},
		// `level` is optional in the Sigma specification, so omitting it makes a rule unrunnable here without making it broken.
		{level: "", wantErr: "no level", wantRejection: true},
		{level: "catastrophic", wantErr: "catastrophic", wantRejection: true},
	}
	for _, tc := range cases {
		t.Run("level="+tc.level, func(t *testing.T) {
			t.Parallel()
			got, err := severityFor(tc.level)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				_, isRejection := errors.AsType[unmappableError](err)
				assert.Equal(t, tc.wantRejection, isRejection, "a level we cannot map is a rejection; a broken file is not")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
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
	assert.Contains(t, err.Error(), "already claimed by", "and where it was first seen")
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

// TestImportedRule_OpenEventResolvesTheSubjectOnce pins that a file_event rule looks its subject up once.
//
// Dropping the accessor that openEventWithSubject returns would make matching and the finding two separate reads of the same pid.
// A materialization commit landing between them lets a rule with a negated Image filter match on an absent image and then attach
// the finding to the very process that should have suppressed it. Issue #762 established this for sudoers_tamper; the same helper
// carries the same obligation here.
func TestImportedRule_OpenEventResolvesTheSubjectOnce(t *testing.T) {
	t.Parallel()

	rule := &importedRule{
		id:         "open-rule",
		title:      "Open rule",
		severity:   api.SeverityMedium,
		eventTypes: []string{"open"},
		// The detection MUST read Image, or the lazy accessor is never invoked during matching and the finding's lookup is the
		// only one either way: the test would then pass whether or not the accessor is reused.
		detection: mustCompileDetection(t, map[string]any{
			"TargetFilename|contains": "/etc/emond.d/",
			"Image|endswith":          "/tee",
		}),
	}
	gr := &countingGraphReader{
		perPIDGraphReader: perPIDGraphReader{},
		proc:              &api.Process{ID: 7, PID: 99, Path: "/usr/bin/tee"},
	}
	evt := api.Event{
		EventID: "e1", HostID: "h1", EventType: "open", TimestampNs: 1,
		Payload: []byte(`{"pid":99,"path":"/etc/emond.d/rules/evil.plist","flags":1537}`),
	}

	findings, err := rule.Evaluate(t.Context(), []api.Event{evt}, gr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, 1, gr.calls, "the subject is read once, and the finding names the process matching saw")
}

// mustCompileDetection builds a single-search detection block for a test rule.
func mustCompileDetection(t *testing.T, fields map[string]any) *sigma.Rule {
	t.Helper()
	compiled, err := sigma.Compile(map[string]any{
		"selection": fields,
		"condition": "selection",
	})
	require.NoError(t, err)
	return compiled
}

// TestPlatformsFor pins the product mapping, which decides which hosts' events a rule is ever scoped to. A wrong mapping makes a
// rule silently inert on the fleet it was written for.
func TestPlatformsFor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		product string
		want    []api.Platform
		wantErr string
	}{
		{product: "macos", want: []api.Platform{api.PlatformDarwin}},
		{product: "windows", want: []api.Platform{api.PlatformWindows}},
		{product: "linux", want: []api.Platform{api.PlatformLinux}},
		{product: "MacOS", want: []api.Platform{api.PlatformDarwin}},
		{product: "aix", wantErr: "aix"},
		{product: "", wantErr: "not a platform"},
	}
	for _, tc := range cases {
		t.Run("product="+tc.product, func(t *testing.T) {
			t.Parallel()
			got, err := platformsFor(tc.product)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestImportedRule_ConsultsNoExclusion pins that an imported rule reads no exclusion, which is what keeps operator tuning in
// detection_rule_settings where a re-sync cannot clobber it.
func TestImportedRule_ConsultsNoExclusion(t *testing.T) {
	t.Parallel()
	assert.Empty(t, (&importedRule{}).SupportedExclusionMatchTypes())
}

// TestParseImported_MalformedFiles pins the hard-error paths: a file that is not a rule at all, rather than a rule this sensor
// cannot run. These fail the import, because they mean the corpus on disk is not the corpus we think it is.
func TestParseImported_MalformedFiles(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		file    string
		wantErr string
	}{
		{"not yaml at all", "\tthis: [is: not\n  valid", "rule.yml"},
		{"a detection block that is not a mapping", `title: T
level: medium
logsource: {category: process_creation, product: macos}
detection: "a string"`, "decode detection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseImported("rule.yml", []byte(tc.file))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.NotErrorIs(t, err, unmappableError{}, "a broken file is not a rule this sensor merely cannot run")
		})
	}
}

// TestParseImported_RefusesAnEmptyFilenameStem pins that a file named exactly `.yml` is refused.
//
// It is a valid directory entry and leaves the rule with no identifier, which findings, exclusions and per-host settings all key
// on. Importing it would create a rule nothing can refer to.
func TestParseImported_RefusesAnEmptyFilenameStem(t *testing.T) {
	t.Parallel()

	body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\ndetection: {sel: {Image: x}, condition: sel}\n")
	_, err := parseImported(".yml", body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no filename stem")
}

// TestImportedRule_SkipsEventsItCannotAct on pins the per-event guards: a batch carrying another event type, a payload with no pid,
// and an event whose subject never materialized all produce nothing rather than an error or a bad finding.
func TestImportedRule_SkipsEventsItCannotActOn(t *testing.T) {
	t.Parallel()

	rule := &importedRule{
		id: "r", title: "R", severity: api.SeverityMedium, eventTypes: []string{"exec"},
		detection: mustCompileDetection(t, map[string]any{"Image|endswith": "/sh"}),
	}

	t.Run("an event of another type", func(t *testing.T) {
		t.Parallel()
		gr := &countingGraphReader{proc: &api.Process{ID: 1, PID: 5, Path: "/bin/sh"}}
		findings, err := rule.Evaluate(t.Context(), []api.Event{{
			EventID: "e", HostID: "h", EventType: "dns_query", Payload: []byte(`{"pid":5}`),
		}}, gr)
		require.NoError(t, err)
		assert.Empty(t, findings)
		assert.Zero(t, gr.calls, "a rule does not touch the graph for an event type it does not consume")
	})

	t.Run("a payload carrying no pid", func(t *testing.T) {
		t.Parallel()
		gr := &countingGraphReader{proc: &api.Process{ID: 1, PID: 5, Path: "/bin/sh"}}
		findings, err := rule.Evaluate(t.Context(), []api.Event{{
			EventID: "e", HostID: "h", EventType: "exec", Payload: []byte(`{"path":"/bin/sh"}`),
		}}, gr)
		require.NoError(t, err, "a malformed payload is skipped, not raised: one bad event must not discard the batch")
		assert.Empty(t, findings)
	})

	t.Run("an event the detection does not match", func(t *testing.T) {
		t.Parallel()
		gr := &countingGraphReader{proc: &api.Process{ID: 1, PID: 5, Path: "/bin/zsh"}}
		findings, err := rule.Evaluate(t.Context(), []api.Event{{
			EventID: "e", HostID: "h", EventType: "exec", Payload: []byte(`{"pid":5,"path":"/bin/zsh"}`),
		}}, gr)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("a subject that never materialized", func(t *testing.T) {
		t.Parallel()
		gr := &countingGraphReader{proc: nil} // the row is not there
		findings, err := rule.Evaluate(t.Context(), []api.Event{{
			EventID: "e", HostID: "h", EventType: "exec", TimestampNs: 1, Payload: []byte(`{"pid":5,"path":"/bin/sh"}`),
		}}, gr)
		require.NoError(t, err)
		assert.Empty(t, findings, "with no process row there is nothing to attach a finding to")
	})
}

// erroringGraphReader fails every process lookup, so a test can pin what an imported rule does when the graph is unavailable.
type erroringGraphReader struct {
	*perPIDGraphReader
	err error
}

func (r erroringGraphReader) GetProcessByPID(_ context.Context, _ string, _ int, _ int64) (*api.Process, error) {
	return nil, r.err
}

// TestImportedRule_PropagatesAGraphFailure pins that a graph failure surfaces rather than being read as "no match".
//
// The distinction matters: a lookup that failed and a process that genuinely has no parent are the same absence at match time, and
// treating a failure as a miss would turn an outage into silence across every imported rule at once.
func TestImportedRule_PropagatesAGraphFailure(t *testing.T) {
	t.Parallel()

	rule := &importedRule{
		id: "r", title: "R", severity: api.SeverityMedium, eventTypes: []string{"exec"},
		detection: mustCompileDetection(t, map[string]any{"ParentImage|endswith": "/launchd"}),
	}
	gr := erroringGraphReader{perPIDGraphReader: &perPIDGraphReader{}, err: errors.New("graph unavailable")}

	_, err := rule.Evaluate(t.Context(), []api.Event{{
		EventID: "e", HostID: "h", EventType: "exec", TimestampNs: 1, Payload: []byte(`{"pid":5,"ppid":1,"path":"/bin/sh"}`),
	}}, gr)
	require.Error(t, err, "a graph failure must not be reported as no match")
	assert.Contains(t, err.Error(), "graph unavailable")
}

// TestLoadImported_ADuplicateIDIsCaughtEvenWhenTheFirstFileIsRejected pins that the stem check runs before parsing.
//
// Recording an id only after a successful parse would let a rejected file leave its id unclaimed, so a second file with the same
// stem would import and the collision would go unreported. Which rule an operator got would then depend on which of the two
// happened to be unmappable.
func TestLoadImported_ADuplicateIDIsCaughtEvenWhenTheFirstFileIsRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// `a/` sorts before `b/`, so the unmappable file is parsed first.
	unmappable := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\ndetection: {sel: {OriginalFileName: x}, condition: sel}\n")
	valid := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\ndetection: {sel: {Image: x}, condition: sel}\n")
	for sub, body := range map[string][]byte{"a": unmappable, "b": valid} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, sub, "same.yml"), body, 0o600))
	}

	_, _, err := loadImported(os.DirFS(dir), ".")
	require.Error(t, err, "the collision must fail the import even though the first file is unmappable")
	assert.Contains(t, err.Error(), "same")
}

// TestImportedRule_TechniquesMayBeEmpty pins the contract for a rule whose tags name only tactics.
//
// Several corpus rules carry `attack.persistence` and no `attack.t*`, so they import with no technique mapping. That is upstream's
// choice and not something to invent a mapping for, but it does mean issue #764 cannot register imported rules under the catalog
// invariant that every detection claims a technique. Stated here so that lands as a decision rather than a surprise.
func TestImportedRule_TechniquesMayBeEmpty(t *testing.T) {
	t.Parallel()

	body := []byte("title: T\nlevel: medium\ntags: [attack.persistence]\n" +
		"logsource: {category: process_creation, product: macos}\ndetection: {sel: {Image: x}, condition: sel}\n")
	rule, err := parseImported("tactics_only.yml", body)
	require.NoError(t, err, "a rule with only tactic tags is still a rule")
	assert.Empty(t, rule.Techniques(), "and it claims no technique, because its file names none")
}

// TestCategoryIsInert_RefusesEvenASudoersRule pins the known false refusal in the file_event decision.
//
// The refusal is at CATEGORY granularity, so it also refuses a file_event rule watching /etc/sudoers, which the agent does collect
// and which would therefore run. That is coarser than the refusal contract allows, and it is a deliberate trade: narrowing to path
// scope means comparing each rule's TargetFilename values against the agent's watched prefixes, which is guesswork as soon as a
// rule matches a fragment with |contains, and no rule in the corpus needs it.
//
// This test exists to make the trade visible. Delete it, and narrow categoryIsInert, when a sudoers-watching file_event rule
// actually appears.
func TestCategoryIsInert_RefusesEvenASudoersRule(t *testing.T) {
	t.Parallel()

	body := []byte("title: Sudoers write\nlevel: high\nlogsource: {category: file_event, product: macos}\n" +
		"detection: {sel: {TargetFilename|startswith: '/etc/sudoers'}, condition: sel}\n")
	_, err := parseImported("sudoers.yml", body)
	require.Error(t, err, "known false refusal: this rule WOULD run, and the category refusal does not look at its paths")
	assert.Contains(t, err.Error(), "/etc/sudoers", "the reason names the telemetry, which is what makes the trade auditable")
}

// spec:server-detection-rules-engine/a-rule-this-sensor-cannot-run-is-refused-by-name/a-rule-using-an-unimplemented-sigma-feature-is-refused-not-a-failed-import
// TestParseImported_UnsupportedSigmaIsARejection pins that valid Sigma using a feature this evaluator does not implement is
// reported as one rejection rather than failing the whole import.
//
// Upstream is entitled to ship `windash`, a keyword search or `timeframe`. Those are rules this sensor cannot run, exactly like one
// reading a field it does not collect, and abandoning sixty-odd runnable rules over one of them would be the wrong answer.
func TestParseImported_UnsupportedSigmaIsARejection(t *testing.T) {
	t.Parallel()

	// A keyword search: a list of bare strings rather than field matchers. Valid Sigma, unsupported here.
	body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\n" +
		"detection:\n  keywords:\n    - 'some phrase'\n  condition: keywords\n")
	_, err := parseImported("keywords.yml", body)
	require.Error(t, err)

	_, isRejection := errors.AsType[unmappableError](err)
	assert.True(t, isRejection, "an unsupported feature is a rejection, so the rest of the corpus still imports")
	assert.Contains(t, err.Error(), "keyword", "the reason names the feature, so a re-sync report says what to build")
}

// spec:server-detection-rules-engine/a-rule-this-sensor-cannot-run-is-refused-by-name/a-structurally-invalid-detection-block-fails-the-import
// TestParseImported_MalformedDetectionIsAHardError is the counterpart to TestParseImported_UnsupportedSigmaIsARejection.
//
// Both are sigma.Compile failures and they must not be treated alike. A rule using a feature we have not built is one we cannot run,
// so it is rejected and the corpus loads on. A detection block that is structurally broken is a defect in a file this repository
// vendored, and the reason for checking the corpus in at all is that such a file fails loudly instead of vanishing into a rejection
// list. Collapsing the two, in either direction, is a bug we have already shipped once.
func TestParseImported_MalformedDetectionIsAHardError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		detect string
	}{
		{"condition names a search that does not exist", "detection: {sel: {Image: /bin/sh}, condition: nope}"},
		{"no condition at all", "detection: {sel: {Image: /bin/sh}}"},
		{"condition of neither Sigma form", "detection: {sel: {Image: /bin/sh}, condition: 7}"},
		{"a list entry that is neither a field map nor a keyword", "detection: {sel: [{Image: /bin/sh}, 7], condition: sel}"},
		{"no searches", "detection: {condition: sel}"},
		{"search with an empty field map", "detection: {sel: {}, condition: sel}"},
		{"unclosed parenthesis", "detection: {sel: {Image: /bin/sh}, condition: '(sel'}"},
		{"a list entry that is not a field map and not a keyword", "detection: {sel: [3], condition: sel}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\n" + tc.detect + "\n")
			_, err := parseImported("broken.yml", body)
			require.Error(t, err)

			_, isRejection := errors.AsType[unmappableError](err)
			assert.False(t, isRejection, "a broken vendored file must fail the import, not join the rejections")
			assert.Contains(t, err.Error(), "broken.yml", "a hard error names the file so the failure is actionable")
		})
	}
}

// TestImportedCorpus_MatchesTheVendoredManifest pins that no vendored rule file has been edited since it was imported.
//
// The fixture README claims these files are byte-identical to upstream. Nothing offline can check them against upstream, but the
// half that actually decays is local drift: an edit made to get a rule to load, or a stray reformat, silently turns "what SigmaHQ
// ships" into "what we found convenient", and the re-sync in #763 would then diff against a corpus that is no longer the baseline
// it claims to be. Counting loads and rejections does not catch that, because an edited rule can still load.
//
// Regenerate MANIFEST.sha256 as part of a deliberate re-sync, never to make this test pass.
func TestImportedCorpus_MatchesTheVendoredManifest(t *testing.T) {
	t.Parallel()

	// One filesystem for both halves, so the manifest and the files it pins are read through the same root.
	fsys := os.DirFS("testdata/imported")
	manifest, err := fs.ReadFile(fsys, "MANIFEST.sha256")
	require.NoError(t, err)

	want := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(manifest)), "\n") {
		sum, name, found := strings.Cut(line, "  ")
		require.True(t, found, "malformed manifest line %q", line)
		want[name] = sum
	}

	got := map[string]string{}
	require.NoError(t, fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(name, ".yml") {
			return err
		}
		body, readErr := fs.ReadFile(fsys, name)
		if readErr != nil {
			return readErr
		}
		got[name] = fmt.Sprintf("%x", sha256.Sum256(body))
		return nil
	}))

	// Compared as whole maps so one assertion reports every edit, addition and deletion at once rather than stopping at the first.
	assert.Equal(t, want, got, "a vendored rule file differs from the manifest; regenerate it only as part of a deliberate re-sync")
}

// spec:server-detection-rules-engine/a-rule-this-sensor-cannot-run-is-refused-by-name/a-structurally-invalid-detection-block-fails-the-import
// TestParseImported_CorruptionOutranksInapplicability pins the ORDER the two verdicts are decided in.
//
// A file can be refusable for more than one cause at once, and the causes are not peers. Whether the detection block is intact is a
// fact about the file, so a corrupted one this repository vendored must fail the import whether or not this sensor would ever have
// run the rule. Whether we collect its telemetry is a fact about this sensor, and only decides which REJECTION reason to report.
//
// Deciding applicability first hid corruption: a broken rule in a category we do not map was reported as an ordinary rejection and
// the import went green, which is the failure checking the corpus in is supposed to make impossible.
func TestParseImported_CorruptionOutranksInapplicability(t *testing.T) {
	t.Parallel()

	const broken = "detection: {sel: {Image: /bin/sh}, condition: nope}\n"

	t.Run("a broken detection block fails even when the category maps to nothing we collect", func(t *testing.T) {
		t.Parallel()

		body := []byte("title: T\nlevel: high\nlogsource: {category: registry_set, product: windows}\n" + broken)
		_, err := parseImported("windows.yml", body)
		require.Error(t, err)

		_, isRejection := errors.AsType[unmappableError](err)
		assert.False(t, isRejection, "corruption is a fact about the file, so it must not be masked by inapplicability")
	})

	t.Run("a broken detection block fails even when the category is inert", func(t *testing.T) {
		t.Parallel()

		body := []byte("title: T\nlevel: high\nlogsource: {category: file_event, product: macos}\n" + broken)
		_, err := parseImported("inert.yml", body)
		require.Error(t, err)

		_, isRejection := errors.AsType[unmappableError](err)
		assert.False(t, isRejection, "corruption is a fact about the file, so it must not be masked by inert telemetry")
	})

	t.Run("an unsupported feature yields to the more useful applicability reason", func(t *testing.T) {
		t.Parallel()

		// Refusable twice over: a keyword search we have not built, in a category the agent does not collect. The reason a
		// re-sync can act on is the telemetry one, so that is the one reported.
		body := []byte("title: T\nlevel: high\nlogsource: {category: registry_set, product: windows}\n" +
			"detection:\n  keywords:\n    - 'some phrase'\n  condition: keywords\n")
		_, err := parseImported("both.yml", body)
		require.Error(t, err)

		_, isRejection := errors.AsType[unmappableError](err)
		require.True(t, isRejection)
		assert.Contains(t, err.Error(), "maps to no event type")
	})
}
