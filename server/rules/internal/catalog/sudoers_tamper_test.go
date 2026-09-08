package catalog

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// TestSudoersTamper_TechniquesMapping pins the MITRE ATT&CK mapping.
func TestSudoersTamper_TechniquesMapping(t *testing.T) {
	t.Parallel()
	r := &SudoersTamper{}
	assert.Equal(t, []string{"T1548.003"}, r.Techniques())
}

// TestSudoersTamper_ExcludedEdgeCases pins the contract of excluded(): a nil resolver always returns false; a resolver entry hits
// per its match-type semantics (here path_glob, which is exact when the entry has no `*`).
func TestSudoersTamper_ExcludedEdgeCases(t *testing.T) {
	t.Parallel()
	rNoList := &SudoersTamper{}
	assert.False(t, rNoList.excluded("/usr/sbin/visudo", "host-a"),
		"nil resolver must return false for any path")

	r := &SudoersTamper{Exclusions: &fakeExclusions{entries: []fakeExcl{
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/usr/sbin/visudo"},
	}}}
	assert.True(t, r.excluded("/usr/sbin/visudo", "host-a"))
	assert.False(t, r.excluded("/usr/local/bin/visudo", "host-a"),
		"a literal entry is exact-path; no PATH-walk fallback")
	assert.False(t, r.excluded("", "host-a"),
		"empty path must not match a non-empty entry")
}

// TestSudoersTamper_ExcludedCanonicalizesPrivatePaths pins the #482 path-alias fix at the rule layer. sudoers_tamper matches the
// WRITER process path (proc.Path), not the sudoers file, so the exclusion value is an aliasable writer (a staged installer under /var
// or /tmp): /var and /tmp are macOS symlinks into /private and ESF may report either form, so an exclusion written in one form must
// suppress a writer reported in the other. Exercised through the rule's own excluded() so a matcher regression is caught in real shape.
// spec:server-detection-rules-engine/path-exclusions-match-across-the-macos-private-firmlink-boundary/an-exclusion-matches-the-aliased-form-of-the-candidate-path
func TestSudoersTamper_ExcludedCanonicalizesPrivatePaths(t *testing.T) {
	t.Parallel()
	// Operator excluded the bare /var writer form; the rule sees the /private/var form ESF reports.
	rVar := &SudoersTamper{Exclusions: &fakeExclusions{entries: []fakeExcl{
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/var/db/munki/installer"},
	}}}
	assert.True(t, rVar.excluded("/private/var/db/munki/installer", "host-a"),
		"a /var writer exclusion must suppress the /private/var form ESF can report")

	// And the reverse: operator excluded the /private form; the rule sees the bare form.
	rPrivate := &SudoersTamper{Exclusions: &fakeExclusions{entries: []fakeExcl{
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/private/tmp/*"},
	}}}
	assert.True(t, rPrivate.excluded("/tmp/installer", "host-a"),
		"a /private/tmp writer glob must suppress the bare /tmp form")
}

// TestSudoersTamper_MalformedPayload exercises the unmarshal-failure path: the fast-path bytes.Contains lets it through (the magic
// substring is present), then unmarshal trips and the rule drops the event silently.
func TestSudoersTamper_MalformedPayload(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := api.Event{
		EventID:     "sud-malformed",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"path":"/etc/sudoers", "flags":`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "malformed payload must be dropped silently")
}

// TestSudoersTamper_OpenRaceWithoutProcess covers the proc==nil race
// guard. Mirrors the same shape as the other open-keyed rules.
func TestSudoersTamper_OpenRaceWithoutProcess(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := api.Event{
		EventID:     "sud-race",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"pid":99999,"path":"/etc/sudoers","flags":1}`),
	}
	require.NoError(t, s.InsertEvents(ctx, []api.Event{evt}))
	require.NoError(t, s.ProcessBatch(ctx, []api.Event{evt}))

	findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "race against process materialisation must skip silently")
}

// boundRenameEvent builds a `file_rename` event the way the file-tamper client emits one, bound to a writer.
func boundRenameEvent(t *testing.T, sourcePath, path, subject string) *sigmabind.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"pid": 7, "source_path": sourcePath, "path": path})
	require.NoError(t, err)
	ev, err := sigmabind.NewOpenEventLazy(
		api.Event{EventID: "e", EventType: "file_rename", Payload: payload},
		func() (string, error) { return subject, nil })
	require.NoError(t, err)
	return ev
}

// spec:server-detection-rules-engine/sudoers-tampering-matches-the-files-sudo-loads/a-rename-that-makes-a-file-loadable-fires
// spec:server-detection-rules-engine/sudoers-tampering-matches-the-files-sudo-loads/a-rename-to-a-name-sudo-ignores-does-not-fire
//
// The atomic-replace evasion (#917) and its boundary. A rename is judged on its DESTINATION, because the destination is what
// decides whether the file is policy sudo will parse; where it came from does not change that.
//
// The first case is the evasion the rule used to miss entirely: `mv /tmp/x /etc/sudoers.d/evil` produces no CREATE and no
// WRITE on a watched path, so before renames were read there was no event to match.
func TestSudoersTamper_RenameIsJudgedOnItsDestination(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		sourcePath string
		path       string
		want       bool
	}{
		{"promotion from outside the watched set", "/tmp/x", "/etc/sudoers.d/evil", true},
		{"promotion from a sibling temp file", "/etc/sudoers.d/evil.tmp", "/etc/sudoers.d/evil", true},
		{"promotion onto the main file", "/tmp/x", "/etc/sudoers", true},
		{"private form of the destination", "/tmp/x", "/private/etc/sudoers.d/evil", true},
		// The destination is a name sudo skips, so nothing became policy and there is nothing to alert on. This is the
		// shape a legitimate editor produces on its way IN, and the shape #933 was firing on.
		{"destination sudo ignores, dotted", "/etc/sudoers.d/evil", "/etc/sudoers.d/evil.tmp", false},
		{"destination sudo ignores, trailing tilde", "/tmp/x", "/etc/sudoers.d/evil~", false},
		// Renaming a live fragment AWAY destroys policy rather than granting it. Delivered by the extension, deliberately
		// not a finding for this rule, which is about escalation. Tracked as #934.
		{"rename out of the watched set", "/etc/sudoers.d/evil", "/tmp/x", false},
		{"unrelated rename", "/tmp/a", "/tmp/b", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := boundRenameEvent(t, tc.sourcePath, tc.path, "/bin/mv")
			assert.Equal(t, tc.want, sudoersDetection().Matches(ev),
				"rename %s -> %s", tc.sourcePath, tc.path)
		})
	}
}

// The rename's two paths reach the detection under the Sigma names the file_rename category defines, and they are not
// interchangeable: TargetFilename is the destination and SourceFilename the origin. Pinned because swapping them would leave
// every case in the table above passing for the wrong reason on a symmetric input, and because a rule keying on the source
// would report the attacker's scratch path as the tampered file.
func TestSudoersTamper_RenameSuppliesBothPathsUnderTheirSigmaNames(t *testing.T) {
	t.Parallel()
	ev := boundRenameEvent(t, "/tmp/staged", "/etc/sudoers.d/evil", "/bin/mv")

	target, ok := ev.Field("TargetFilename")
	require.True(t, ok, "a rename must supply TargetFilename")
	assert.Equal(t, []string{"/etc/sudoers.d/evil"}, target, "TargetFilename is the DESTINATION")

	source, ok := ev.Field("SourceFilename")
	require.True(t, ok, "a rename must supply SourceFilename")
	assert.Equal(t, []string{"/tmp/staged"}, source, "SourceFilename is the ORIGIN")
}

// spec:server-detection-rules-engine/sudoers-tampering-matches-the-files-sudo-loads/a-rename-that-makes-a-file-loadable-fires
//
// The atomic-replace evasion through the RULE, not through the detection block alone.
//
// The distinction earns its own test. Every other rename assertion here calls sudoersDetection().Matches directly, which
// exercises the Sigma condition and nothing else; the rule's own event-type guard sits upstream of that. Deleting `file_rename`
// from the guard leaves every one of those assertions passing and the evasion wide open again, which is exactly what a mutation
// run showed: the guard survived while three sibling mutants died. This is the test that kills it.
func TestSudoersTamper_RenameFiresThroughTheRule(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	const pid = 5150
	setup := []api.Event{
		{EventID: "ren-fork", HostID: "fixture-host", TimestampNs: 1, EventType: "fork",
			Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, pid))},
		{EventID: "ren-exec", HostID: "fixture-host", TimestampNs: 2, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":1,"path":"/bin/mv"}`, pid))},
	}
	require.NoError(t, s.InsertEvents(ctx, setup))
	require.NoError(t, s.ProcessBatch(ctx, setup))

	// `mv /tmp/staged /etc/sudoers.d/evil`: no CREATE and no WRITE ever touch a watched path, which is why this was invisible.
	rename := api.Event{
		EventID:      "ren-evasion",
		HostID:       "fixture-host",
		TimestampNs:  3,
		IngestedAtNs: time.Now().UnixNano(),
		EventType:    "file_rename",
		Payload:      json.RawMessage(fmt.Sprintf(`{"pid":%d,"source_path":"/tmp/staged","path":"/etc/sudoers.d/evil"}`, pid)),
	}
	findings, err := r.Evaluate(ctx, []api.Event{rename}, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "a rename that makes a file into sudo policy must fire")
	assert.Equal(t, "sudoers_tamper", findings[0].RuleID)

	// And the boundary, through the same path: a destination sudo skips is not policy, so it is not a finding.
	ignored := rename
	ignored.EventID = "ren-ignored"
	ignored.Payload = json.RawMessage(fmt.Sprintf(`{"pid":%d,"source_path":"/tmp/staged","path":"/etc/sudoers.d/evil.tmp"}`, pid))
	findings, err = r.Evaluate(ctx, []api.Event{ignored}, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "a name sudo will never parse grants nothing, so it is not an escalation")
}

// spec:server-detection-rules-engine/sudoers-tampering-matches-the-files-sudo-loads/a-drop-into-a-loadable-name-fires
// spec:server-detection-rules-engine/sudoers-tampering-matches-the-files-sudo-loads/a-write-to-a-name-sudo-ignores-does-not-fire
//
// The write half of the narrowing (#933), stated as a table so the boundary is auditable at a glance rather than inferred
// from the regex.
//
// sudoers(5): sudo reads each file in /etc/sudoers.d "skipping file names that end in '~' or contain a '.' character".
// Verified on macOS 26.3 with three files of identical content differing only in name: zzdotless loaded, zz.dotted and
// zztilde~ did not. So a name sudo skips grants nothing, and alerting on one reports an escalation that cannot have happened.
//
// The `.tmp` row is the false positive itself: one `visudo -f /etc/sudoers.d/<name>` writes `<name>.tmp` as a sibling inside
// the watched prefix, and the old pattern fired on it every time.
func TestSudoersTamper_MatchesOnlyTheNamesSudoLoads(t *testing.T) {
	t.Parallel()
	const emitted = 0x1 | 0x200 | 0x400 // the constant synthetic flag set FileTamperSubscriber stamps
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/sudoers", true},
		{"/private/etc/sudoers", true},
		{"/etc/sudoers.d/evil", true},
		{"/private/etc/sudoers.d/edr-uat", true},
		{"/etc/sudoers.d/a", true},
		// A tilde that is not the LAST character does not make sudo skip the file, so narrowing must not over-reach.
		{"/etc/sudoers.d/foo~bar", true},
		{"/etc/sudoers.d/zz-visudo.tmp", false},
		{"/etc/sudoers.d/backup.old", false},
		{"/etc/sudoers.d/fragment~", false},
		{"/etc/sudoers.d/", false},
		{"/etc/sudoers.d/nested/deeper", false},
		{"/etc/sudoersX", false},
		{"/etc/passwd", false},
		// visudo's temp file for the MAIN sudoers file, which lands outside the watched set entirely.
		{"/etc/sudoers.tmp", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, sudoersDetection().Matches(boundOpenEvent(t, tc.path, emitted, "/usr/bin/tee")),
				"path %q", tc.path)
		})
	}
}

// The finding sentence has to say what happened, and for a rename "opened for writing" is false: nothing was opened, and the
// file became live sudo policy without its contents ever being written on this host. Live QA against the dev server produced
// exactly that wrong sentence (`/bin/mv opened /etc/sudoers.d/evil for writing`), which is what this pins.
func TestSudoersTamper_DescriptionSaysWhatHappened(t *testing.T) {
	t.Parallel()

	rename := sudoersDescription("file_rename", "/bin/mv",
		boundRenameEvent(t, "/tmp/staged", "/etc/sudoers.d/evil", "/bin/mv"))
	assert.Contains(t, rename, "renamed a file onto /etc/sudoers.d/evil", "the matched element, and the verb that changes triage")
	assert.Contains(t, rename, "making it sudo policy")
	assert.NotContains(t, rename, "opened", "a rename opens nothing, and saying so sends an analyst looking for a write")
	// The source is attacker-chosen and is not what the detection matched on, so it stays out of the alert feed.
	assert.NotContains(t, rename, "/tmp/staged",
		"attacker-controlled content is withheld where naming the matched element is sufficient")

	write := sudoersDescription("open", "/usr/bin/tee",
		boundOpenEvent(t, "/etc/sudoers", 0x1|0x200|0x400, "/usr/bin/tee"))
	assert.Contains(t, write, "/usr/bin/tee opened /etc/sudoers for writing", "the write wording is unchanged")
}

// The byte prefilter depends on an invariant that is invisible from this package, and review is what surfaced it.
//
// Swift's JSONEncoder escapes forward slashes, so the real extension puts `"\/etc\/sudoers.d\/evil"` on the wire and the
// agent uploads those bytes unchanged. A raw scan for `/etc/sudoers` finds NOTHING in that form, which this pins directly.
//
// What makes the rule work anyway is `event_queue.payload` being a MySQL JSON column: MySQL normalizes `\/` to `/` on storage,
// so the bytes the rule receives have already been unescaped. Every other test in this file marshals with Go's encoding/json,
// which does not escape slashes, so none of them can tell whether that invariant holds.
//
// The end-to-end guard lives in the detection context, where event_queue is a real table
// (TestSudoersRenameSurvivesSlashEscapingThroughTheQueue). What belongs HERE is the hazard itself: if someone reads the
// prefilter and assumes it matches wire bytes, this test is the correction.
func TestSudoersTamper_PrefilterDoesNotMatchTheExtensionsWireBytes(t *testing.T) {
	t.Parallel()

	wire := []byte(`{"pid":6021,"source_path":"\/tmp\/staged","path":"\/etc\/sudoers.d\/evil"}`)
	assert.NotContains(t, string(wire), "/etc/sudoers",
		"the extension's own encoding does not contain the magic substring; the prefilter relies on storage normalizing it")

	normalized := []byte(`{"pid":6021,"source_path":"/tmp/staged","path":"/etc/sudoers.d/evil"}`)
	assert.Contains(t, string(normalized), "/etc/sudoers",
		"what the JSON column hands back does contain it, which is the form the rule is written against")
}
