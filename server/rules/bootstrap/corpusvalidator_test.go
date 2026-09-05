package bootstrap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// ruleDoc renders a minimal but real Sigma document, so these tests exercise the actual loader rather than a shape invented here.
func ruleDoc(path, id, title, detection string) rulecontentapi.Document {
	return rulecontentapi.Document{Path: path, Content: []byte(
		"title: " + title + "\n" +
			"id: " + id + "\n" +
			"status: test\n" +
			"description: fixture\n" +
			"author: test\n" +
			"logsource:\n    category: process_creation\n    product: macos\n" +
			"detection:\n" + detection +
			"level: medium\n")}
}

const simpleDetection = "    selection:\n        Image|endswith: '/osascript'\n    condition: selection\n"

// TestCorpusValidator_AcceptsALoadableCorpus is the baseline the refusal tests are read against: without it, a validator that
// refused everything would pass every other test here.
func TestCorpusValidator_AcceptsALoadableCorpus(t *testing.T) {
	t.Parallel()
	warnings, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		ruleDoc("imported/a_rule.yml", "11111111-1111-4111-8111-111111111111", "A Rule", simpleDetection),
		ruleDoc("authored/b_rule.yml", "22222222-2222-4222-8222-222222222222", "B Rule", simpleDetection),
	})
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// spec:rule-content/authored-content-is-validated-by-the-loader/a-document-colliding-with-an-existing-rule-identity-is-refused
//
// TestCorpusValidator_RefusesACollidingIdentity is the reason validation takes the whole document set rather than the one document
// being written. A rule's identity is its file STEM, so these two documents claim one identity from different directories, and the
// loader treats that as an error refusing the entire corpus rather than as one bad document.
//
// Validating the submitted document alone would accept this happily, and the deployment would then fail to load any corpus at all
// and fall back to the copy embedded in its binary. That is the single worst outcome an authoring surface can produce, which is
// why it gets its own test rather than riding on the generic refusal case.
func TestCorpusValidator_RefusesACollidingIdentity(t *testing.T) {
	t.Parallel()
	_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		ruleDoc("imported/same_stem.yml", "11111111-1111-4111-8111-111111111111", "First", simpleDetection),
		ruleDoc("authored/same_stem.yml", "22222222-2222-4222-8222-222222222222", "Second", simpleDetection),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same_stem", "the reason must name the colliding identity, since that is what the operator fixes")
}

// spec:rule-content/authored-content-is-validated-by-the-loader/a-pattern-too-expensive-to-match-is-reported-and-does-not-run
//
// TestCorpusValidator_UnaffordablePatternIsReportedNotSilent pins what an operator actually gets for a pattern above the cost
// limit #852 introduced, and the answer is a warning rather than a refusal. Worth a test that asserts the MESSAGE rather than
// only that something happened: an earlier version of this test asserted merely that validation errored, and it passed for the
// wrong reason entirely, because the single-document corpus tripped the separate "nothing here can run" check instead.
//
// Warning rather than refusal is the loader's own posture and it is the right one to inherit. The rule is not loaded, so it
// cannot slow evaluation, which is the property #767 asks for. And the message names the file, the search, the field, the cost
// and the limit, so an operator who meant it to run knows exactly what to change.
func TestCorpusValidator_UnaffordablePatternIsReportedNotSilent(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("a", 100000)
	warnings, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		ruleDoc("imported/runnable.yml", "11111111-1111-4111-8111-111111111111", "Runnable", simpleDetection),
		ruleDoc("authored/expensive.yml", "33333333-3333-4333-8333-333333333333", "Expensive",
			"    selection:\n        Image|contains: '"+huge+"'\n    condition: selection\n"),
	})
	require.NoError(t, err, "one unaffordable rule does not stop the rest of the corpus loading")
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "authored/expensive.yml", "names the file the operator opens")
	assert.Contains(t, warnings[0], `field "Image"`, "names the field to fix, which is the whole point of the message")
	assert.Contains(t, warnings[0], "above the limit of", "and says it is a limit rather than a mystery")
	assert.Contains(t, warnings[0], "will not run", "so the operator is not left thinking it is active")
}

// TestCorpusValidator_RefusesMalformedContent pins that a document which is not a rule at all is refused rather than stored and
// discovered at the next load.
func TestCorpusValidator_RefusesMalformedContent(t *testing.T) {
	t.Parallel()
	_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		{Path: "authored/broken.yml", Content: []byte("title: [unclosed\n  nonsense: :\n")},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken.yml", "the reason must name the file, which is what the operator opens")
}

// spec:rule-content/authored-content-is-validated-by-the-loader/a-corpus-in-which-nothing-can-run-is-refused
//
// TestCorpusValidator_RefusesACorpusThatWouldRunNothing covers the case both load paths treat as "fall back to the embedded
// corpus": documents present, every one of them refused. Accepting that would silently discard the operator's whole corpus, so it
// is an error here even though each individual refusal is only a warning.
func TestCorpusValidator_RefusesACorpusThatWouldRunNothing(t *testing.T) {
	t.Parallel()
	// OriginalFileName is a Sysmon field with no macOS equivalent, which the binder refuses per-rule rather than fatally.
	unmappable := ruleDoc("authored/unmappable.yml", "44444444-4444-4444-8444-444444444444", "Unmappable",
		"    selection:\n        OriginalFileName: 'x.exe'\n    condition: selection\n")
	_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{unmappable})
	require.Error(t, err, "a corpus where nothing can run would drop the deployment to its embedded copy")
	assert.Contains(t, err.Error(), "no document in the proposed corpus can run")
}

// TestCorpusValidator_UnrunnableRuleBesideARunnableOneIsAWarning is the other side of that line, and the distinction matters: a
// corpus written for a fleet of sensors legitimately contains rules this one cannot map, and refusing the write over one would
// stop an operator storing a rule the deployment would simply not run.
func TestCorpusValidator_UnrunnableRuleBesideARunnableOneIsAWarning(t *testing.T) {
	t.Parallel()
	warnings, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		ruleDoc("imported/runnable.yml", "11111111-1111-4111-8111-111111111111", "Runnable", simpleDetection),
		ruleDoc("authored/unmappable.yml", "44444444-4444-4444-8444-444444444444", "Unmappable",
			"    selection:\n        OriginalFileName: 'x.exe'\n    condition: selection\n"),
	})
	require.NoError(t, err, "one unrunnable rule must not block a corpus that otherwise loads")
	require.Len(t, warnings, 1, "but the operator must be told it will not fire")
	assert.Contains(t, warnings[0], "unmappable.yml")
	assert.Contains(t, warnings[0], "will not run")
}
