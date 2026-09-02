package catalog

import (
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/a-rule-whose-identifier-cannot-be-persisted-is-refused-at-load/every-shipped-rule-identifier-is-storable
//
// TestEveryShippedRuleIDIsStorable is the gate that would have caught issue #832 in CI instead of on a dev server.
//
// It measures the REAL catalog, which is the only thing that catches this class: every unit test around rule identifiers uses
// short hand-written ones, and the defect arrived with an imported corpus whose identifiers come from upstream filenames. One of
// the 79 shipped rules is 70 characters, and every rule_id column was VARCHAR(64), so the identifier was storable nowhere and
// refused nowhere.
//
// Asserted per rule rather than on the maximum, so a failure names the offending rule instead of a number.
func TestEveryShippedRuleIDIsStorable(t *testing.T) {
	t.Parallel()

	rules := New(nil)
	require.NotEmpty(t, rules, "an empty catalog would make this assertion vacuous")

	for _, r := range rules {
		id := r.ID()
		// Runes, matching the validator and the column. Counting bytes here would fail a shipped identifier of at most 255
		// multibyte characters that the loaders accept and every column stores, which is the same confusion the validator had
		// (issue #835 review). Every shipped id is ASCII today, so this is agreement rather than a live difference, and a gate
		// that measures something other than what it guards stops being a gate the moment that changes.
		assert.LessOrEqualf(t, utf8.RuneCountInString(id), api.MaxRuleIDLen,
			"rule %q has a %d-character identifier, over the %d-character limit: it cannot be stored, and a rule whose alerts "+
				"cannot be persisted wedges the event queue of any host it matches on",
			id, utf8.RuneCountInString(id), api.MaxRuleIDLen)
		assert.NotEmptyf(t, id, "a rule with no identifier collides with every other rule that has none")
	}
}

// spec:server-detection-rules-engine/a-rule-whose-identifier-cannot-be-persisted-is-refused-at-load/an-over-long-identifier-is-refused-when-the-rule-set-loads
//
// TestLoadImported_RefusesAnOverLongRuleID drives the IMPORTED LOADER, not the helper it calls.
//
// Written because the sibling test below, which asserts the helper is shared, turned out to be an inert guard for exactly this:
// removing the call from imported.go left it passing, since it exercises checkRuleIDLength directly.
//
// An in-memory FS rather than a temp directory, and that is not a convenience. Writing the file first was the obvious approach and
// it FAILED with "file name too long": a filesystem caps one path component at 255 bytes, so an imported identifier, which is the
// filename stem, cannot exceed about 251 characters on disk. The production corpus is a go:embed of a real directory tree, so
// today that bound sits below api.MaxRuleIDLen and this refusal cannot fire for it.
//
// The guard is kept and tested anyway, through the one FS shape that can express the case, because loadImported takes an fs.FS
// rather than a directory and the runtime rule-pack loading in #766 is precisely a corpus that does not come from a filesystem.
// The alternative was to delete the imported call site as unreachable and rediscover the need later, from a defect rather than a
// test.
func TestLoadImported_RefusesAnOverLongRuleID(t *testing.T) {
	t.Parallel()

	body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\n" +
		"detection: {sel: {Image: x}, condition: sel}\n")
	// The stem is the identifier, so the NAME is what has to be over the limit.
	stem := strings.Repeat("l", api.MaxRuleIDLen+1)
	fsys := fstest.MapFS{
		"process_creation/" + stem + ".yml": &fstest.MapFile{Data: body},
	}

	_, _, err := loadImported(fsys, ".")

	require.Error(t, err, "a rule whose identifier cannot be stored must not load")
	assert.Contains(t, err.Error(), "over the", "the message must say the identifier is over the limit")
	assert.Contains(t, err.Error(), "wedges the event queue",
		"and must say what it costs, because the consequence is not guessable from a length error")
}

// TestLoadPack_RefusesAnOverLongRuleID drives the PACK loaders, not the helper they call.
//
// The same inert-guard problem the imported-loader test above was written for: asserting validateRuleID rejects a long id proves
// nothing about whether loadPackParams or loadPackDetections calls it, and removing either call left the suite green (issue #835
// review). Both are driven, because they are separate loaders over the same files and either one registering a rule the other
// refused would be worse than neither refusing.
//
// A pack identifier is arbitrary YAML text rather than a filename, so unlike the imported path this refusal is reachable with no
// qualification about filesystem limits.
func TestLoadPack_RefusesAnOverLongRuleID(t *testing.T) {
	t.Parallel()

	tooLong := strings.Repeat("p", api.MaxRuleIDLen+1)
	body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\n" +
		"detection: {sel: {Image: x}, condition: sel}\n" +
		"x-engine:\n  rule_id: " + tooLong + "\n  algorithm: ancestor_walk_temp_exec\n")
	fsys := fstest.MapFS{"pack/over_long.yml": &fstest.MapFile{Data: body}}

	for _, tc := range []struct {
		name string
		load func() error
	}{
		{name: "params loader", load: func() error { _, err := loadPack(fsys); return err }},
		{name: "detections loader", load: func() error { _, err := loadDetections(fsys); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.load()
			require.Error(t, err, "a pack rule whose identifier cannot be stored must not load")
			assert.Contains(t, err.Error(), "over the", "the message must say the identifier is over the limit")
		})
	}
}

// TestLoadImported_RefusesAnOverLongRuleIDEvenWhenTheRuleIsOtherwiseRejected pins that the refusal is a PREFLIGHT.
//
// It was not, and that was a defect. parseImported returns SOFT rejections for a rule using a field the binder cannot map, and
// those are recorded and skipped rather than failing the load, so an over-long filename whose rule also used an unsupported field
// exited at that earlier return and loadImported SUCCEEDED. The hard refusal the requirement asks for simply did not happen
// (issue #835 review).
//
// The file here is both: an unstorable name AND a rule the binder cannot map. Before the fix this loaded with a soft rejection;
// now the name is refused before anything is parsed.
func TestLoadImported_RefusesAnOverLongRuleIDEvenWhenTheRuleIsOtherwiseRejected(t *testing.T) {
	t.Parallel()

	// A field with no mapping, so parseImported would reject this file softly if it ever got that far.
	body := []byte("title: T\nlevel: medium\nlogsource: {category: process_creation, product: macos}\n" +
		"detection: {sel: {ThisFieldHasNoMapping: x}, condition: sel}\n")
	stem := strings.Repeat("s", api.MaxRuleIDLen+1)
	fsys := fstest.MapFS{"process_creation/" + stem + ".yml": &fstest.MapFile{Data: body}}

	_, rejected, err := loadImported(fsys, ".")

	require.Error(t, err,
		"an unstorable identifier must FAIL the load, not be recorded as a soft rejection alongside unmappable rules")
	assert.Contains(t, err.Error(), "over the")
	assert.Empty(t, rejected, "the load failed, so nothing should have been parsed far enough to be softly rejected")
}

// TestCheckRuleIDLengthIsSharedByEveryLoader pins that the length refusal covers the IMPORTED path, not just the pack loaders.
//
// This is the path that mattered: an imported rule's identifier is an upstream filename, so a corpus re-sync can introduce a name
// this repo never chose and no column can store. Guarding only the pack loaders would have left the actual source of issue #832
// unguarded while every other test passed.
//
// Asserted through the shared helper AND through validateRuleID, so a refactor that gives one path its own copy of the limit
// fails here rather than drifting quietly.
func TestCheckRuleIDLengthIsSharedByEveryLoader(t *testing.T) {
	t.Parallel()

	tooLong := strings.Repeat("z", api.MaxRuleIDLen+1)

	require.Error(t, checkRuleIDLength("upstream.yml", tooLong), "the imported loader calls this directly")
	require.Error(t, validateRuleID("pack.yml", tooLong), "and the pack loaders reach it through validateRuleID")
	assert.NoError(t, checkRuleIDLength("upstream.yml", strings.Repeat("z", api.MaxRuleIDLen)),
		"the limit is inclusive: an identifier exactly at the width the columns declare must be accepted")
}

// spec:server-detection-rules-engine/a-rule-whose-identifier-cannot-be-persisted-is-refused-at-load/an-over-long-identifier-is-refused-when-the-rule-set-loads
//
// TestValidateRuleID covers the load-time refusal both pack loaders share.
//
// Boundary cases on both sides of the limit, because an off-by-one here is the whole defect in miniature: a limit that admits one
// character too many stores nothing and refuses nothing, which is the state issue #832 describes.
func TestValidateRuleID(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		id      string
		wantErr string
	}{
		{name: "ordinary identifier", id: "suspicious_exec"},
		{name: "the longest shipped identifier", id: "proc_creation_macos_remote_access_tools_teamviewer_incoming_connection"},
		{name: "exactly at the limit", id: strings.Repeat("a", api.MaxRuleIDLen)},
		{name: "one over the limit", id: strings.Repeat("a", api.MaxRuleIDLen+1), wantErr: "over the"},
		{name: "empty", id: "", wantErr: "is empty"},
		// The limit counts CHARACTERS because VARCHAR(n) does. These two are the boundary that separates a character count from
		// a byte count: 255 three-byte runes is 765 bytes, so a byte comparison refuses an identifier every column can store,
		// and 256 of them must still be refused. An identifier this shape is not idiomatic, but nothing enforces ASCII and a
		// convention is not a reason to measure the wrong thing (issue #835 review).
		{name: "multibyte, exactly at the limit", id: strings.Repeat("日", api.MaxRuleIDLen)},
		{name: "multibyte, one over the limit", id: strings.Repeat("日", api.MaxRuleIDLen+1), wantErr: "over the"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateRuleID("some_rule.yml", tc.id)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			// The file is named, because a loader failure an operator cannot trace to a file is a failure they cannot fix.
			assert.Contains(t, err.Error(), "some_rule.yml", "the refusal has to say which pack file it came from")
		})
	}
}
