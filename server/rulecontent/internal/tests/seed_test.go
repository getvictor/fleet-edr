//go:build integration

package tests

import (
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	rulecontentmysql "github.com/fleetdm/edr/server/rulecontent/internal/mysql"
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

// TestSeed_StorageIsLossless is the storage half of this change's end-to-end claim.
//
// Content must round-trip byte-identically, under the same path the loader reads it by, or storing the corpus could change which
// detections run. Asserted on CONTENT rather than parsed rules deliberately: the parser lives in the `rules` context and has its
// own test that a supplied FS parses identically to the embedded one, so each half is proven where its code lives.
//
// A FIXTURE rather than the real vendored corpus, and that is a boundary decision rather than convenience. An earlier version of
// this test reached into rules/bootstrap for the embedded corpus, which contradicted this context's own arch-go stanza: it permits
// no dependency on `rules`, because rulecontent produces content and consumes nothing from the evaluator. Losslessness is a
// property of the store rather than of any particular content, so a fixture exercising the shapes that break naive storage proves
// it without the import.
func TestSeed_StorageIsLossless(t *testing.T) {
	t.Parallel()
	rc, store := newContext(t)
	ctx := t.Context()

	// Shapes chosen for what they would break: nesting (paths must survive whole, not be flattened to a basename), a byte over
	// 127 (encoding must not mangle it), a blank line and trailing newline (whitespace is significant in YAML), and content with
	// a quote and a backslash (escaping).
	source := fstest.MapFS{
		"imported/proc/nested_rule.yml": &fstest.MapFile{Data: []byte("title: nested\ndetection:\n  a: 1\n")},
		"imported/unicode_rule.yml":     &fstest.MapFile{Data: []byte("title: caf\u00e9 \u2014 na\u00efve\n")},
		"imported/whitespace_rule.yml":  &fstest.MapFile{Data: []byte("title: ws\n\n  indented: true\n")},
		"imported/escaping_rule.yml":    &fstest.MapFile{Data: []byte(`title: "quoted \\ backslash"` + "\n")},
		"imported/README.md":            &fstest.MapFile{Data: []byte("# packaging, not content")},
	}
	include := func(p string) bool { return strings.HasSuffix(p, ".yml") }

	seeded, err := rc.SeedFrom(ctx, source, "imported", include)
	require.NoError(t, err)
	require.True(t, seeded)

	want := map[string][]byte{}
	require.NoError(t, fs.WalkDir(source, "imported", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !include(path) {
			return walkErr
		}
		body, readErr := fs.ReadFile(source, path)
		if readErr != nil {
			return readErr
		}
		want[path] = body
		return nil
	}))
	require.Len(t, want, 4, "the fixture must contribute every rule file, or this asserts less than it appears to")

	docs, err := store.Documents(ctx)
	require.NoError(t, err)
	got := make(map[string][]byte, len(docs))
	for _, d := range docs {
		got[d.Path] = d.Content
	}
	assert.Equal(t, want, got,
		"every document must round-trip unchanged, under the same path the loader reads it by, and packaging must not be stored")
}
