package catalog

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// A file event whose acting process has no record, past the grace unless said otherwise: the case every test here hinges on.
func orphanOpen(ingestedAtNs int64) api.Event {
	return api.Event{
		EventID: "orphan-open", HostID: "h1", EventType: "open", TimestampNs: 1, IngestedAtNs: ingestedAtNs,
		Payload: []byte(`{"pid":99,"path":"/tmp/drop/evil.plist","flags":1537}`),
	}
}

func openRule(t *testing.T, id string, fields map[string]any) *importedRule {
	t.Helper()
	return &importedRule{
		id: id, title: id, severity: api.SeverityMedium, eventTypes: []string{"open"},
		detection: mustCompileDetection(t, fields),
	}
}

// spec:server-detection-rules-engine/sigma-abandons-are-charged-to-the-reader/a-match-with-no-process-to-name-is-counted
//
// The detection matched, and the finding was dropped because there is no process to attach it to. That is a detection lost,
// charged to the rule that matched.
func TestSigmaAbandon_AMatchWithNoProcessToNameIsCounted(t *testing.T) {
	t.Parallel()
	rule := openRule(t, "matches-on-target", map[string]any{"TargetFilename|startswith": "/tmp/drop/"})
	scope := &api.BatchScope{}
	findings, err := rule.EvaluateScoped(t.Context(), scope, []api.Event{orphanOpen(pastEveryGrace())}, &perPIDGraphReader{})

	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, 1, scope.MaterializationAbandoned("matches-on-target"))
}

// spec:server-detection-rules-engine/sigma-abandons-are-charged-to-the-reader/only-the-rule-that-read-the-process-is-charged
//
// The core of issue #1169. Rules in a batch share one memoized subject lookup per event, so charging the lookup would charge every
// rule. Only a rule whose decision read the process (here, Image on a file event, which IS the acting process's path) lost a
// detection; one that decided on the file alone did not.
func TestSigmaAbandon_OnlyTheRuleThatReadTheProcessIsCharged(t *testing.T) {
	t.Parallel()
	readsImage := openRule(t, "reads-image", map[string]any{
		"TargetFilename|startswith": "/tmp/drop/",
		"Image|endswith":            "/tee",
	})
	fileOnly := openRule(t, "file-only", map[string]any{"TargetFilename|startswith": "/somewhere/else/"})
	scope := &api.BatchScope{}
	gr := &perPIDGraphReader{}
	events := []api.Event{orphanOpen(pastEveryGrace())}

	for _, r := range []*importedRule{readsImage, fileOnly} {
		findings, err := r.EvaluateScoped(t.Context(), scope, events, gr)
		require.NoError(t, err)
		assert.Empty(t, findings)
	}
	assert.Equal(t, 1, scope.MaterializationAbandoned("reads-image"), "its decision depended on the missing process")
	assert.Zero(t, scope.MaterializationAbandoned("file-only"), "it decided on the file and never read the process")
}

func parentReader(t *testing.T) *importedRule {
	t.Helper()
	return &importedRule{
		id: "parent-reader", title: "parent-reader", severity: api.SeverityMedium, eventTypes: []string{"exec"},
		detection: mustCompileDetection(t, map[string]any{"ParentImage|endswith": "/Microsoft Word"}),
	}
}

func shellExec(ingestedAtNs int64) api.Event {
	return api.Event{
		EventID: "exec-shell", HostID: "h1", EventType: "exec", TimestampNs: 1, IngestedAtNs: ingestedAtNs,
		Payload: []byte(`{"pid":99,"ppid":98,"path":"/bin/sh","args":["sh"]}`),
	}
}

// spec:server-detection-rules-engine/sigma-abandons-are-charged-to-the-reader/a-missing-parent-is-not-an-abandon
//
// On an exec, ParentImage is found from the subject's row. A present subject whose parent is missing is not the rule giving up on
// its subject: a parent can predate the capture and never materialize.
func TestSigmaAbandon_AMissingParentIsNotAnAbandon(t *testing.T) {
	t.Parallel()
	gr := &perPIDGraphReader{procByPID: map[int]*api.Process{99: {ID: 9, PID: 99, PPID: 98, Path: "/bin/sh"}}}
	scope := &api.BatchScope{}
	_, err := parentReader(t).EvaluateScoped(t.Context(), scope, []api.Event{shellExec(pastEveryGrace())}, gr)

	require.NoError(t, err)
	assert.Zero(t, scope.MaterializationAbandoned("parent-reader"))
}

// spec:server-detection-rules-engine/sigma-abandons-are-charged-to-the-reader/a-missing-subject-hides-the-parent-too
//
// With the subject itself missing there is no row to find the parent from, so a detection reading ParentImage decided without it.
// That is the subject never arriving, and it is charged. Inside the grace it is a retry: the absent ParentImage used to be read as
// "no parent matched" and the event dropped for good.
func TestSigmaAbandon_AMissingSubjectHidesTheParentToo(t *testing.T) {
	t.Parallel()
	scope := &api.BatchScope{}
	_, err := parentReader(t).EvaluateScoped(t.Context(), scope, []api.Event{shellExec(pastEveryGrace())}, &perPIDGraphReader{})
	require.NoError(t, err)
	assert.Equal(t, 1, scope.MaterializationAbandoned("parent-reader"))

	young := &api.BatchScope{}
	_, err = parentReader(t).EvaluateScoped(t.Context(), young, []api.Event{shellExec(time.Now().UnixNano())}, &perPIDGraphReader{})
	require.ErrorIs(t, err, api.ErrProcessNotYetMaterialized, "a young subject is a retry, not an absent parent")
	assert.Zero(t, young.MaterializationAbandoned("parent-reader"))
}

// Inside the grace the missing process is a retry, not an abandon, whichever way the rule would have decided.
func TestSigmaAbandon_AYoungMissIsARetry(t *testing.T) {
	t.Parallel()
	rule := openRule(t, "matches-on-target", map[string]any{"TargetFilename|startswith": "/tmp/drop/"})
	scope := &api.BatchScope{}
	_, err := rule.EvaluateScoped(t.Context(), scope, []api.Event{orphanOpen(time.Now().UnixNano())}, &perPIDGraphReader{})

	require.ErrorIs(t, err, api.ErrProcessNotYetMaterialized)
	assert.Zero(t, scope.MaterializationAbandoned("matches-on-target"))
}

// A resolved process is no abandon, however the rule decided.
func TestSigmaAbandon_AResolvedProcessIsNotAnAbandon(t *testing.T) {
	t.Parallel()
	gr := &perPIDGraphReader{procByPID: map[int]*api.Process{99: {ID: 7, PID: 99, Path: "/usr/bin/tee"}}}
	for _, r := range []*importedRule{
		openRule(t, "matches", map[string]any{"TargetFilename|startswith": "/tmp/drop/"}),
		openRule(t, "reads-image-no-match", map[string]any{"TargetFilename|startswith": "/tmp/drop/", "Image|endswith": "/cat"}),
	} {
		scope := &api.BatchScope{}
		_, err := r.EvaluateScoped(t.Context(), scope, []api.Event{orphanOpen(pastEveryGrace())}, gr)
		require.NoError(t, err)
		assert.Zerof(t, scope.MaterializationAbandoned(r.id), "rule %s", r.id)
	}
}

// Every converted Sigma rule attaches its finding to the subject process, so a subject that never materialized costs each one a
// detection, and each has its own call site where the count could be lost, which is why each is driven here. For most the loss is
// a match with no process to name; for shell_from_office it is the non-match itself, since its ParentImage is found through the
// subject and cannot be read without it.
func TestSigmaAbandon_EveryConvertedRuleCountsADetectionItsSubjectCostIt(t *testing.T) {
	t.Parallel()
	exec := func(pid int, path string, args ...string) api.Event {
		payload := `{"pid":` + itoa(pid) + `,"ppid":1,"path":"` + path + `","args":` + jsonStrings(args) + `,"uid":0,"gid":0}`
		return api.Event{EventID: "e-" + path, HostID: "h1", EventType: "exec", TimestampNs: 1, IngestedAtNs: pastEveryGrace(),
			Payload: []byte(payload)}
	}
	word := &api.Process{ID: 1, PID: 4500, Path: "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"}
	cases := []struct {
		name string
		rule api.AbandonCounter
		evt  api.Event
		gr   *perPIDGraphReader
	}{
		{"credential_keychain_dump", &CredentialKeychainDump{}, exec(4200, "/usr/bin/security", "security", "dump-keychain"),
			&perPIDGraphReader{}},
		{"dyld_insert", &DyldInsert{}, exec(4400, "/usr/bin/env", "env", "DYLD_INSERT_LIBRARIES=/tmp/inject.dylib", "/bin/ls"),
			&perPIDGraphReader{}},
		// The parent matched, the shell's own record did not arrive.
		{"shell_from_office", &ShellFromOffice{}, api.Event{
			EventID: "e-bash", HostID: "h1", EventType: "exec", TimestampNs: 1, IngestedAtNs: pastEveryGrace(),
			Payload: []byte(`{"pid":4501,"ppid":4500,"path":"/bin/bash","args":["bash","-c","curl x | sh"],"uid":501,"gid":20}`),
		}, &perPIDGraphReader{procByPID: map[int]*api.Process{4500: word}}},
		{"sudoers_tamper", &SudoersTamper{}, api.Event{
			EventID: "e-open", HostID: "h1", EventType: "open", TimestampNs: 1, IngestedAtNs: pastEveryGrace(),
			Payload: []byte(`{"pid":11100,"path":"/etc/sudoers","flags":1537}`),
		}, &perPIDGraphReader{}},
		{"sudoers_destroyed", &SudoersDestroyed{}, api.Event{
			EventID: "e-del", HostID: "h1", EventType: "file_delete", TimestampNs: 1, IngestedAtNs: pastEveryGrace(),
			Payload: []byte(`{"pid":12200,"path":"/private/etc/sudoers.d/admins"}`),
		}, &perPIDGraphReader{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scope := &api.BatchScope{}
			findings, err := tc.rule.EvaluateScoped(t.Context(), scope, []api.Event{tc.evt}, tc.gr)
			require.NoError(t, err)
			assert.Empty(t, findings)
			assert.Equal(t, 1, scope.MaterializationAbandoned(tc.rule.ID()), "the detection the missing subject cost is counted")
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func jsonStrings(s []string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
