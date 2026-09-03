//go:build integration

package tests

import (
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

// spec:rule-content/an-unavailable-or-unusable-store-leaves-detections-running/content-that-fails-to-load-does-not-stop-detection
//
// TestStore_UnreachableStoreReportsAnErrorNotAnEmptyCorpus is a correctness test that happens to also be a coverage one.
//
// The consumer treats the two outcomes DIFFERENTLY on purpose: an error means fall back and say so, while an empty corpus means
// fall back silently, because an unseeded store is the expected first-boot state. So a store that answered "no documents" when its
// connection was gone would send an unreachable database down the silent path, and the operator would get no signal at all while
// running the build's rules instead of theirs.
//
// A closed handle is the cheapest honest way to reach these paths: it is a real driver error rather than a stubbed one.
func TestStore_UnreachableStoreReportsAnErrorNotAnEmptyCorpus(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	require.NoError(t, rulecontentbootstrap.ApplySchema(t.Context(), db))
	s := rulecontentmysql.New(db)
	require.NoError(t, db.Close())

	ctx := t.Context()

	docs, err := s.Documents(ctx)
	require.Error(t, err, "an unreachable store must not be indistinguishable from an empty one")
	assert.Empty(t, docs)

	_, err = s.Version(ctx)
	assert.Error(t, err, "and the version a replica polls must fail loudly rather than read as zero")

	_, err = s.IsEmpty(ctx)
	assert.Error(t, err, "and the seed's guard must fail rather than conclude the corpus is empty and overwrite it")

	_, err = s.Replace(ctx, nil)
	assert.Error(t, err, "and a replace must fail rather than report a version it did not write")
}

// TestBootstrap_RejectsAMissingHandle covers the constructor's contract.
func TestBootstrap_RejectsAMissingHandle(t *testing.T) {
	t.Parallel()

	_, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{})
	require.Error(t, err, "a context with no store cannot serve rule content, so it must not construct")
	assert.Contains(t, err.Error(), "DB")

	assert.Error(t, rulecontentbootstrap.ApplySchema(t.Context(), nil),
		"and applying a schema to no handle is a programming error, not a no-op")
}

// TestBootstrap_CorpusAccessorReturnsTheStore covers the published seam consumers hold.
func TestBootstrap_CorpusAccessorReturnsTheStore(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	require.NoError(t, rulecontentbootstrap.ApplySchema(t.Context(), db))
	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)

	corpus := rc.Corpus()
	require.NotNil(t, corpus, "consumers hold this and nothing else, so a nil here is a dead context")

	version, err := corpus.Version(t.Context())
	require.NoError(t, err, "and it must be usable, not merely non-nil")
	assert.Zero(t, version)
}

// TestSeed_SourceWithNoRuleDocuments covers the case where there is nothing to seed.
//
// Not an error: a deployment may legitimately ship no vendored corpus, and refusing to start would make running with an empty
// corpus impossible even deliberately. Reported at WARN because it is surprising enough to say out loud, unlike an already-seeded
// corpus which says nothing.
func TestSeed_SourceWithNoRuleDocuments(t *testing.T) {
	t.Parallel()
	rc, store := newContext(t)
	ctx := t.Context()

	// A source holding only packaging, which the include predicate rejects.
	source := fstest.MapFS{"imported/README.md": &fstest.MapFile{Data: []byte("# not a rule")}}

	seeded, err := rc.SeedFrom(ctx, source, "imported", func(p string) bool { return false })
	require.NoError(t, err, "nothing to seed is not a failure")
	assert.False(t, seeded)

	empty, err := store.IsEmpty(ctx)
	require.NoError(t, err)
	assert.True(t, empty, "and the corpus is left empty rather than half-written")
}

// TestSeed_UnreadableSourceIsReported covers the walk's error path.
func TestSeed_UnreadableSourceIsReported(t *testing.T) {
	t.Parallel()
	rc, _ := newContext(t)

	_, err := rc.SeedFrom(t.Context(), fstest.MapFS{}, "no-such-root", nil)
	require.Error(t, err, "a seed source that cannot be walked must be reported, not silently skipped")
	assert.Contains(t, err.Error(), "no-such-root")
}

// TestCorpus_ReplaceReportsADocumentItCannotStore covers the per-document write failure.
//
// Paths come from walking a source tree, so their length is not something this code chooses. A document whose path does not fit
// the column has to be reported: silently dropping it would leave the corpus short one rule, and a missing detection that nothing
// complained about is the hardest kind to notice. The whole replace fails, which is the same all-or-nothing rule that applies to
// content the loader rejects.
func TestCorpus_ReplaceReportsADocumentItCannotStore(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	_, err := s.Replace(ctx, []api.Document{
		{Path: "imported/fine.yml", Content: []byte("ok")},
		{Path: "imported/" + strings.Repeat("deep/", 60) + "too-long.yml", Content: []byte("ok")},
	})

	require.Error(t, err, "a document that cannot be stored must fail the replace, not be skipped")
	assert.Contains(t, err.Error(), "too-long.yml", "and the error must name the document, or there is nothing to fix")

	docs, dErr := s.Documents(ctx)
	require.NoError(t, dErr)
	assert.Empty(t, docs, "and the transaction rolls back, so no half-written corpus is left behind")
}

// TestBootstrap_DefaultsTheLogger covers the nil-logger path, which is a real state rather than a hypothetical: the context is
// constructed by callers that may not have wired one yet.
func TestBootstrap_DefaultsTheLogger(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	require.NoError(t, rulecontentbootstrap.ApplySchema(t.Context(), db))

	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db})
	require.NoError(t, err, "a missing logger must not prevent construction")

	// Exercise a path that logs, to prove the default is usable rather than merely non-nil.
	_, err = rc.SeedFrom(t.Context(), fstest.MapFS{"imported/x.yml": &fstest.MapFile{Data: []byte("x")}}, "imported", nil)
	require.NoError(t, err)
}
