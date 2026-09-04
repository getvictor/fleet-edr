//go:build integration

package integration

import (
	"io/fs"
	"log/slog"
	"path"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	"github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// The one document the stored corpus holds, named rather than chosen by a walk, and the rule id it imports as.
//
// Naming it is the point. An earlier version took whichever path sorted first, which is a `file_event` rule this sensor refuses
// (it reads telemetry the agent does not collect), so the stored catalog came back EMPTY and every per-rule assertion below was
// vacuous. Both refusable categories sort ahead of `process_creation`, so "first lexically" is close to the worst possible pick.
//
// A rename upstream now fails this test at the read below, with the path in the message, instead of quietly emptying it.
const (
	storedRuleDoc = "imported/process_creation/proc_creation_macos_applescript.yml"
	storedRuleID  = "proc_creation_macos_applescript"
)

// spec:rule-content/rule-content-is-stored-and-is-the-source-the-catalog-loads-from/the-catalog-loads-the-stored-content
//
// TestRuleCorpus_StoredContentIsWhatLoads proves the persisted corpus is actually the source, which nothing else did.
//
// Every other test seeds the corpus from the SAME documents embedded in the build, and an unwired or failing corpus falls back to
// exactly those documents. So all of them would stay green with the supplier removed, which makes them a test of the fallback
// rather than of the feature. Review caught that, correctly.
//
// This distinguishes the two the only way that works: store a corpus that DIFFERS from the embedded one, and assert the rule set
// follows storage. A missing supplier, or a load that quietly falls back, yields the embedded corpus instead and fails here.
func TestRuleCorpus_StoredContentIsWhatLoads(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	logger := slog.New(slog.DiscardHandler)

	ruleContentCtx, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err)

	// The embedded corpus for comparison: this is what a fallback would produce.
	embedded, err := rulesbootstrap.New(ctx, rulesbootstrap.Deps{DB: db, Logger: logger, AuthZ: identitytestkit.AllowAllAuthZ{}})
	require.NoError(t, err)
	embeddedImported := importedIDsIn(t, embedded.ContentService().ActiveRules())
	require.Greater(t, len(embeddedImported), 10, "the embedded corpus is substantial, which is what makes the contrast meaningful")

	// Seed a corpus of exactly ONE rule, taken from the vendored set so it is real content the loader accepts rather than a
	// fixture that might be refused for an unrelated reason. Seeding rather than replacing because a fresh fixture database has
	// the schema but no content, and the seed is the only corpus write reachable from here: replacing is a store method, and this
	// package cannot import another context's internal tree.
	seeded, err := ruleContentCtx.SeedFrom(ctx, vendoredDocument(t, storedRuleDoc),
		rulesbootstrap.EmbeddedCorpusRoot, rulesbootstrap.EmbeddedCorpusIncludes)
	require.NoError(t, err)
	require.True(t, seeded, "the fixture database starts with no corpus, so this must be the write that fills it")

	stored, err := rulesbootstrap.New(ctx, rulesbootstrap.Deps{
		DB: db, Logger: logger, AuthZ: identitytestkit.AllowAllAuthZ{},
		Corpus: ruleContentCtx.Corpus(),
	})
	require.NoError(t, err)
	storedImported := importedIDsIn(t, stored.ContentService().ActiveRules())

	// An EXACT set, not a smaller one. "Fewer than embedded" is also satisfied by loading NOTHING, which is what an unrunnable
	// stored document produces, so an inequality cannot tell a corpus that loaded from one that was consulted and yielded nothing.
	// Naming the id says the stored content was read AND is runnable; requiring nothing else says the embedded corpus was not.
	assert.Equal(t, []string{storedRuleID}, storedImported,
		"the imported half of the rule set must follow the STORED corpus; %d of them means the supplier was ignored or fell back",
		len(embeddedImported))
}

// importedIDsIn returns the sorted ids of the rules that came from the vendored corpus, discarding the natively written ones.
//
// The active rule set is the corpus plus the hand-written catalog, and only the corpus half is what storage governs, so an exact
// total would pin an unrelated number and move whenever a native rule is added. Membership is decided by the corpus itself: a
// document's id is its filename stem (pinned by the catalog's own loader test), so the embedded tree names precisely the ids that
// storage is responsible for. When rules carry their own provenance (issue #765) this becomes a field read instead.
func importedIDsIn(t *testing.T, rules []api.Rule) []string {
	t.Helper()
	return filterCorpusIDs(corpusRuleIDs(t), rules)
}

// corpusRuleIDs is the set of ids the vendored corpus is responsible for. Computed separately from the filter so a caller inside a
// retry callback can build it once, where a require would be the wrong tool.
func corpusRuleIDs(t *testing.T) map[string]bool {
	t.Helper()
	fromCorpus := map[string]bool{}
	require.NoError(t, fs.WalkDir(rulesbootstrap.EmbeddedCorpusFS(), rulesbootstrap.EmbeddedCorpusRoot,
		func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || !rulesbootstrap.EmbeddedCorpusIncludes(p) {
				return walkErr
			}
			fromCorpus[strings.TrimSuffix(path.Base(p), path.Ext(p))] = true
			return nil
		}))
	require.NotEmpty(t, fromCorpus, "the embedded corpus must hold rule documents for this comparison to mean anything")
	return fromCorpus
}

// filterCorpusIDs keeps the rules that came from the corpus, sorted, discarding the natively written ones.
func filterCorpusIDs(fromCorpus map[string]bool, rules []api.Rule) []string {
	var ids []string
	for _, r := range rules {
		if fromCorpus[r.ID()] {
			ids = append(ids, r.ID())
		}
	}
	slices.Sort(ids)
	return ids
}

// vendoredDocument returns an fs.FS holding exactly one real document from the corpus embedded in this build.
//
// Real content rather than a hand-written rule, because the assertion is about WHICH corpus was loaded and a fixture the loader
// refused for its own reasons would produce an empty rule set that looks the same as a corpus that never loaded.
func vendoredDocument(t *testing.T, docPath string) fs.FS {
	t.Helper()
	return fstest.MapFS{docPath: &fstest.MapFile{Data: mustReadVendored(t, docPath)}}
}

// mustReadVendored reads one document out of the corpus embedded in this build, failing with the path when it is not there.
func mustReadVendored(t *testing.T, docPath string) []byte {
	t.Helper()
	body, err := fs.ReadFile(rulesbootstrap.EmbeddedCorpusFS(), docPath)
	require.NoErrorf(t, err, "the corpus must still hold %s; if it was renamed upstream, update storedRuleDoc and storedRuleID", docPath)
	require.True(t, rulesbootstrap.EmbeddedCorpusIncludes(docPath), "and the seed must consider it rule content, or it stores nothing")
	return body
}
