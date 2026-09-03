//go:build integration

package integration

import (
	"io/fs"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
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
	embeddedCount := len(embedded.ContentService().ActiveRules())
	require.Greater(t, embeddedCount, 10, "the embedded corpus is substantial, which is what makes the contrast meaningful")

	// Seed a corpus of exactly ONE rule, taken from the vendored set so it is real content the loader accepts rather than a
	// fixture that might be refused for an unrelated reason. Seeding rather than replacing because a fresh fixture database has
	// the schema but no content, and the seed is the only corpus write reachable from here: replacing is a store method, and this
	// package cannot import another context's internal tree.
	subset, path := oneVendoredDocument(t)
	seeded, err := ruleContentCtx.SeedFrom(ctx, subset, rulesbootstrap.EmbeddedCorpusRoot, rulesbootstrap.EmbeddedCorpusIncludes)
	require.NoError(t, err)
	require.True(t, seeded, "the fixture database starts with no corpus, so this must be the write that fills it")
	t.Logf("stored corpus holds one document: %s", path)

	stored, err := rulesbootstrap.New(ctx, rulesbootstrap.Deps{
		DB: db, Logger: logger, AuthZ: identitytestkit.AllowAllAuthZ{},
		Corpus: ruleContentCtx.Corpus(),
	})
	require.NoError(t, err)
	storedRules := stored.ContentService().ActiveRules()

	assert.Less(t, len(storedRules), embeddedCount,
		"the rule set must follow the STORED corpus; matching the embedded count means the supplier was ignored or fell back")
	for _, r := range storedRules {
		assert.NotEmpty(t, r.ID(), "and every rule it did load must be usable")
	}
}

// oneVendoredDocument returns an fs.FS holding a single real document from the corpus embedded in this build, plus its path.
//
// Real content rather than a hand-written rule, because the assertion is about WHICH corpus was loaded and a fixture the loader
// refused for its own reasons would produce an empty rule set that looks the same as a corpus that never loaded.
func oneVendoredDocument(t *testing.T) (fs.FS, string) {
	t.Helper()
	src := rulesbootstrap.EmbeddedCorpusFS()
	var chosen string
	var body []byte
	err := fs.WalkDir(src, rulesbootstrap.EmbeddedCorpusRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || chosen != "" || !rulesbootstrap.EmbeddedCorpusIncludes(path) {
			return walkErr
		}
		content, readErr := fs.ReadFile(src, path)
		if readErr != nil {
			return readErr
		}
		chosen, body = path, content
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, chosen, "the embedded corpus must hold at least one rule document")
	return fstest.MapFS{chosen: &fstest.MapFile{Data: body}}, chosen
}
