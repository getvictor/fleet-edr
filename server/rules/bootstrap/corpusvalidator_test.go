package bootstrap

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
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
	// Above maxValueCost (4096) but comfortably under the per-document size cap, so this reaches the COST check rather than
	// tripping the size bound first. An earlier version used 100,000 and stopped testing what its name says the moment the size
	// bound landed.
	huge := strings.Repeat("a", 5000)
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

// spec:rule-content/authored-content-is-validated-by-the-loader/a-document-the-loader-would-not-read-is-refused
//
// TestCorpusValidator_RefusesAPathTheLoaderWillNotRead is a hole review found, and the failure mode is the quiet kind.
//
// LoadCorpus walks only the paths IsCorpusFile accepts, so a document stored at authored/rule.yaml is invisible to it. Validation
// would pass on the strength of the OTHER documents, the file would be stored, the operator would be told it worked, and the rule
// would never be evaluated anywhere. Refused rather than warned about, because the operator's whole purpose was to add a rule.
func TestCorpusValidator_RefusesAPathTheLoaderWillNotRead(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"authored/rule.yaml", "authored/rule.txt", "authored/rule"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
				ruleDoc("imported/runnable.yml", "11111111-1111-4111-8111-111111111111", "Runnable", simpleDetection),
				ruleDoc(path, "55555555-5555-4555-8555-555555555555", "Invisible", simpleDetection),
			})
			require.Error(t, err, "a document the loader will not read must not be storable")
			assert.Contains(t, err.Error(), path)
		})
	}
}

// TestCorpusValidator_RefusesAnEmptyCorpus covers deleting the last document, and the consequence is not the obvious one.
//
// An empty store does not mean "no rules". Reload and loadCorpus each KEEP the rule set already in force when the store is empty,
// so the rule an operator just deleted would go on running on every replica while the delete reported success. That is worse than
// refusing, because there is no surface anywhere that would show it.
func TestCorpusValidator_RefusesAnEmptyCorpus(t *testing.T) {
	t.Parallel()
	_, err := CorpusValidator{}.Validate(t.Context(), nil)
	require.Error(t, err, "emptying the corpus leaves the previous rules running indefinitely")
	assert.Contains(t, err.Error(), "no document in the proposed corpus can run")
}

// TestCorpusValidator_RefusesANonCanonicalPath covers an aliasing bug review found, whose shape is worth stating because nothing
// about it is visible at the call site.
//
// rulecontentapi.FS strips ONE leading slash, while storage keys the raw path. So "/authored/x.yml" and "authored/x.yml" are two
// rows that collapse to a single entry the moment the loader is handed them: validation sees one document and passes, both rows
// persist, and every later load silently keeps whichever one the map ends up with. The operator is told both writes succeeded.
func TestCorpusValidator_RefusesANonCanonicalPath(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/authored/x.yml", "./authored/x.yml", "authored/../authored/x.yml", "authored/x.yml/"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
				ruleDoc("imported/runnable.yml", "11111111-1111-4111-8111-111111111111", "Runnable", simpleDetection),
				ruleDoc(path, "66666666-6666-4666-8666-666666666666", "Aliased", simpleDetection),
			})
			require.Error(t, err, "a path that aliases another must not be storable")
		})
	}
}

// TestCorpusValidator_AliasedPathsWouldCollapse is the evidence for WHY the check above exists, rather than an assertion that it
// does. It pins the underlying behaviour of the projection, so if FS ever stops stripping the slash this test says so and the
// guard can be revisited instead of being cargo-culted forward.
func TestCorpusValidator_AliasedPathsWouldCollapse(t *testing.T) {
	t.Parallel()
	docs := []rulecontentapi.Document{
		{Path: "/authored/x.yml", Content: []byte("first")},
		{Path: "authored/x.yml", Content: []byte("second")},
	}
	fsys := rulecontentapi.FS(docs)
	entries, err := fs.ReadDir(fsys, "authored")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "two stored rows project to ONE file, which is the whole problem")
}

// spec:rule-content/authored-content-is-validated-by-the-loader/two-rule-identities-differing-only-by-case-are-refused
//
// TestCorpusValidator_RefusesStemsCollidingOnlyByCase covers a cross-layer inconsistency review found, which is invisible from
// any single layer.
//
// Rule identity is the file stem, and the corpus path column is deliberately BINARY, so storage will hold both Foo.yml and
// foo.yml. But the id is persisted downstream in detection_rule_settings and alerts, whose rule_id columns take the schema default
// collation (utf8mb4_0900_ai_ci) and each carry a unique key over it. To MySQL, "Foo" and "foo" are one value.
//
// So a corpus with both loads two rules the rest of the system cannot tell apart: tuning one tunes the other, and their alerts
// deduplicate into a single row. Comparing stems as exact Go strings was what let that through.
func TestCorpusValidator_RefusesStemsCollidingOnlyByCase(t *testing.T) {
	t.Parallel()
	_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		ruleDoc("imported/Keychain_Dump.yml", "11111111-1111-4111-8111-111111111111", "First", simpleDetection),
		ruleDoc("authored/keychain_dump.yml", "22222222-2222-4222-8222-222222222222", "Second", simpleDetection),
	})
	require.Error(t, err, "two ids MySQL cannot distinguish must not both be storable")
	assert.Contains(t, err.Error(), "case-insensitively",
		"the reason must say WHY, since both files look distinct to anyone reading the corpus")
}

// spec:rule-content/authored-content-is-validated-by-the-loader/an-identifier-outside-the-permitted-character-set-is-refused
//
// TestCorpusValidator_RefusesAnIdentifierOutsideTheCharset is what makes the case-fold above exact rather than hopeful.
//
// utf8mb4_0900_ai_ci is accent-insensitive as well as case-insensitive, so "naive_rule" and "naïve_rule" are one value to MySQL
// while strings.ToLower keeps them apart. Rather than chase a UCA collation in Go, where the obvious approximations all fail in
// the direction that lets a colliding pair through, the charset is narrowed so that case is the only way two ids can differ and
// still collate equal.
func TestCorpusValidator_RefusesAnIdentifierOutsideTheCharset(t *testing.T) {
	t.Parallel()
	for _, stem := range []string{"naïve_rule", "rule with spaces", "rule.with.dots", "rule:colon"} {
		t.Run(stem, func(t *testing.T) {
			t.Parallel()
			_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
				ruleDoc("imported/runnable.yml", "11111111-1111-4111-8111-111111111111", "Runnable", simpleDetection),
				ruleDoc("authored/"+stem+".yml", "77777777-7777-4777-8777-777777777777", "Odd", simpleDetection),
			})
			require.Error(t, err, "an identifier outside the charset makes collation undecidable here")
		})
	}
}

// TestCorpusValidator_AccentedIdentifiersWouldCollateEqual is the evidence for why the charset is narrowed rather than the
// comparison widened. It pins the gap in the obvious approximation, so nobody later "simplifies" the charset check away on the
// grounds that lowercasing already handles it.
func TestCorpusValidator_AccentedIdentifiersWouldCollateEqual(t *testing.T) {
	t.Parallel()
	assert.NotEqual(t, strings.ToLower("naive_rule"), strings.ToLower("naïve_rule"),
		"lowercasing keeps these apart, while the collation storing them does not: that gap is the reason for the charset")
}

// spec:rule-content/authored-content-is-validated-by-the-loader/an-oversized-corpus-is-refused
//
// TestCorpusValidator_BoundsTheCorpus covers the denial of service that needs no malformed input at all. Every edit revalidates
// the whole set and every replica reparses it on each version change, so an operator with only valid rules can make both
// arbitrarily slow unless something bounds the corpus.
func TestCorpusValidator_BoundsTheCorpus(t *testing.T) {
	t.Parallel()

	t.Run("one oversized document", func(t *testing.T) {
		t.Parallel()
		huge := ruleDoc("authored/big.yml", "88888888-8888-4888-8888-888888888888", "Big", simpleDetection)
		huge.Content = append(huge.Content, []byte("\n# "+strings.Repeat("p", maxDocumentBytes))...)
		_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{huge})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most")
	})

	t.Run("too many documents", func(t *testing.T) {
		t.Parallel()
		docs := make([]rulecontentapi.Document, 0, maxCorpusDocuments+1)
		for i := range maxCorpusDocuments + 1 {
			docs = append(docs, rulecontentapi.Document{
				Path: fmt.Sprintf("authored/rule_%d.yml", i), Content: []byte("title: x\n"),
			})
		}
		_, err := CorpusValidator{}.Validate(t.Context(), docs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most")
	})
}

// TestCorpusValidator_RefusesAnOverlongPath covers the gap between what the loader bounds and what storage accepts.
//
// The loader bounds the rule IDENTIFIER, which is the file stem. The path carries directories too, so a perfectly canonical .yml
// with a long enough prefix passed every check, parsed fine, and then failed as a raw database error against the VARCHAR(255)
// column. An operator would see an internal failure rather than a refusal naming what to shorten.
func TestCorpusValidator_RefusesAnOverlongPath(t *testing.T) {
	t.Parallel()
	// A short, legal stem under a directory prefix that alone exceeds the column.
	long := "authored/" + strings.Repeat("d/", 130) + "rule.yml"
	require.Greater(t, len(long), maxDocumentPathLen, "fixture must actually exceed the bound it is testing")

	_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		ruleDoc("imported/runnable.yml", "11111111-1111-4111-8111-111111111111", "Runnable", simpleDetection),
		ruleDoc(long, "99999999-9999-4999-8999-999999999999", "Deep", simpleDetection),
	})
	require.Error(t, err, "a path storage cannot hold must be refused here, not by the database")
	assert.Contains(t, err.Error(), "at most 255 characters")
}

// spec:rule-content/authored-content-is-validated-by-the-loader/an-identifier-already-used-by-a-shipped-rule-is-refused
//
// TestCorpusValidator_RefusesAnIdentifierAlreadyShipped covers a collision the loader structurally cannot see.
//
// checkDuplicateStems compares a corpus against ITSELF, which is all the loader is given. NewWithCorpus then appends those rules
// to the list this project registers in code and checks nothing. So a corpus file named suspicious_exec.yml produces a second rule
// under an id already in use, and because per-rule settings and alert deduplication are keyed by that id, tuning one would tune
// both while the catalog listed two rules under one identity.
func TestCorpusValidator_RefusesAnIdentifierAlreadyShipped(t *testing.T) {
	t.Parallel()
	for _, stem := range []string{"suspicious_exec", "Suspicious_Exec", "dyld_insert"} {
		t.Run(stem, func(t *testing.T) {
			t.Parallel()
			_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
				ruleDoc("authored/"+stem+".yml", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Shadow", simpleDetection),
			})
			require.Error(t, err, "a corpus rule must not claim an id this deployment already ships")
			assert.Contains(t, err.Error(), "already the id of a rule this deployment ships")
		})
	}
}

// TestBuiltInRuleIDs_IsNotEmpty guards the check above against the way it would fail silently. If BuiltInRuleIDs ever returned
// nothing, every collision test would still pass by never colliding, and the guard would be inert.
func TestBuiltInRuleIDs_IsNotEmpty(t *testing.T) {
	t.Parallel()
	ids := catalog.BuiltInRuleIDs()
	require.NotEmpty(t, ids, "an empty list would make the collision check silently inert")
	assert.Contains(t, ids, "suspicious_exec")
}

// TestCorpusValidator_RefusesADocumentShadowedByAnAncestor covers the last member of the aliasing family review found, reached
// from the opposite direction to the leading-slash case.
//
// "authored/a.yml" and "authored/a.yml/hidden.yml" are both valid relative paths and both store, but the projection makes the
// first an ordinary FILE, so the walk stops there and never reaches the second. Validation would pass on the parent alone and the
// child would be stored, reported as stored, and never evaluated.
func TestCorpusValidator_RefusesADocumentShadowedByAnAncestor(t *testing.T) {
	t.Parallel()
	_, err := CorpusValidator{}.Validate(t.Context(), []rulecontentapi.Document{
		ruleDoc("authored/a.yml", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "Parent", simpleDetection),
		ruleDoc("authored/a.yml/hidden.yml", "ffffffff-ffff-4fff-8fff-ffffffffffff", "Hidden", simpleDetection),
	})
	require.Error(t, err, "a document the walk cannot reach must not be storable")
	assert.Contains(t, err.Error(), "would never reach it")
}

// TestCorpusValidator_ShadowedDocumentWouldBeInvisible pins the projection behaviour the guard above exists for, so the guard is
// revisited rather than removed if the walk ever starts descending into such a path.
func TestCorpusValidator_ShadowedDocumentWouldBeInvisible(t *testing.T) {
	t.Parallel()
	fsys := rulecontentapi.FS([]rulecontentapi.Document{
		{Path: "authored/a.yml", Content: []byte("parent")},
		{Path: "authored/a.yml/hidden.yml", Content: []byte("hidden")},
	})
	var walked []string
	require.NoError(t, fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			walked = append(walked, p)
		}
		return nil
	}))
	assert.NotContains(t, walked, "authored/a.yml/hidden.yml",
		"the walk cannot reach a document nested under a file, which is exactly why it must be refused")
}
