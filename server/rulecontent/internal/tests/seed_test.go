//go:build integration

package tests

import (
	"io/fs"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	rulecontentmysql "github.com/fleetdm/edr/server/rulecontent/internal/mysql"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

func newContext(t *testing.T) (*rulecontentbootstrap.RuleContent, *rulecontentmysql.Store) {
	t.Helper()
	db := full.Open(t)
	require.NoError(t, rulecontentbootstrap.ApplySchema(t.Context(), db))
	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	return rc, rulecontentmysql.New(db)
}

// spec:rule-content/seeding-never-overwrites-content-that-is-already-there/an-empty-store-is-seeded
// spec:rule-content/seeding-never-overwrites-content-that-is-already-there/a-store-holding-content-is-left-alone
//
// TestSeed_PopulatesAnEmptyCorpusAndThenLeavesItAlone covers the guard that makes the seed safe to run on every boot.
//
// Keyed on EMPTY rather than on a version, deliberately. Once an operator can author rules (#767), a seed that ran whenever the
// stored version looked older than the build would overwrite their work on the next restart. Empty is the only condition under
// which the seed can be certain it is not destroying something.
func TestSeed_PopulatesAnEmptyCorpusAndThenLeavesItAlone(t *testing.T) {
	t.Parallel()
	rc, store := newContext(t)
	ctx := t.Context()

	source := fstest.MapFS{
		"imported/one.yml": &fstest.MapFile{Data: []byte("one")},
		"imported/two.yml": &fstest.MapFile{Data: []byte("two")},
	}

	seeded, err := rc.SeedFrom(ctx, source, "imported", nil)
	require.NoError(t, err)
	assert.True(t, seeded, "an empty corpus is seeded")

	// Stand in for content an operator authored after the seed.
	_, err = store.Replace(ctx, []api.Document{{Path: "imported/authored.yml", Content: []byte("mine")}})
	require.NoError(t, err)

	seededAgain, err := rc.SeedFrom(ctx, source, "imported", nil)
	require.NoError(t, err)
	assert.False(t, seededAgain, "a non-empty corpus is left alone; seeding again would discard authored content")

	docs, err := store.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "imported/authored.yml", docs[0].Path, "the authored corpus survives a second boot")
}

// TestSeed_FromTheEmbeddedCorpusIsLossless is the storage half of this change's end-to-end claim.
//
// Seeding from the build's own corpus and reading it back must return byte-identical documents. Asserted on CONTENT rather than on
// parsed rules deliberately: the parser lives in the rules context and has its own test that a supplied FS parses identically to
// the embed, so proving losslessness here keeps each half testable where its code lives instead of reaching across the boundary
// ADR-0021 just drew.
func TestSeed_FromTheEmbeddedCorpusIsLossless(t *testing.T) {
	t.Parallel()
	rc, store := newContext(t)
	ctx := t.Context()

	source := rulesbootstrap.EmbeddedCorpusFS()
	root := rulesbootstrap.EmbeddedCorpusRoot

	seeded, err := rc.SeedFrom(ctx, source, root, rulesbootstrap.EmbeddedCorpusIncludes)
	require.NoError(t, err)
	require.True(t, seeded)

	want := map[string][]byte{}
	require.NoError(t, fs.WalkDir(source, root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		// Only rule content is expected in storage: the vendored directory also carries a README and a checksum manifest of the
		// snapshot as checked in, and neither describes the stored corpus once it can be edited.
		if !rulesbootstrap.EmbeddedCorpusIncludes(path) {
			return nil
		}
		body, readErr := fs.ReadFile(source, path)
		if readErr != nil {
			return readErr
		}
		want[path] = body
		return nil
	}))
	require.NotEmpty(t, want, "the vendored corpus is not empty, so a seed that stored nothing is a failure not a no-op")

	docs, err := store.Documents(ctx)
	require.NoError(t, err)
	got := make(map[string][]byte, len(docs))
	for _, d := range docs {
		got[d.Path] = d.Content
	}
	assert.Equal(t, want, got,
		"every vendored document must round-trip through storage unchanged, under the same path the loader reads it by")
}
