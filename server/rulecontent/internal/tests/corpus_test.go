//go:build integration

// Package tests holds the rulecontent context's integration tests: the corpus store against a real MySQL.
package tests

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentmysql "github.com/fleetdm/edr/server/rulecontent/internal/mysql"
	"github.com/fleetdm/edr/server/testdb/full"
)

func newStore(t *testing.T) *rulecontentmysql.Store {
	t.Helper()
	// full.Open applies every context's schema, rulecontent's included, so there is nothing to hand-apply here.
	return rulecontentmysql.New(full.Open(t))
}

// spec:rule-content/rule-content-is-stored-and-is-the-source-the-catalog-loads-from/replacing-content-removes-what-is-no-longer-in-it
//
// TestCorpus_ReplaceIsWholeCorpus pins that a replace is not an upsert.
//
// A corpus is the unit that is valid or not: a rule deleted upstream has to disappear, and a reader must never see half of one
// version and half of another. Per-document upserts would leave a removed rule running forever, which is the shape of bug that
// presents as a detection nobody can explain the origin of.
func TestCorpus_ReplaceIsWholeCorpus(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	first, err := s.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/b.yml", Content: []byte("b")},
	})
	require.NoError(t, err)

	// b is gone upstream, c is new.
	second, err := s.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a2")},
		{Path: "imported/c.yml", Content: []byte("c")},
	})
	require.NoError(t, err)
	assert.Greater(t, second, first, "every replace advances the version a replica polls")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	paths := make([]string, 0, len(docs))
	for _, d := range docs {
		paths = append(paths, d.Path)
	}
	assert.Equal(t, []string{"imported/a.yml", "imported/c.yml"}, paths,
		"a document absent from the new corpus must be gone, not left behind by an upsert")
	assert.Equal(t, []byte("a2"), docs[0].Content, "and a changed document must carry its new content")
}

// TestCorpus_DocumentsAreOrderedByPath pins load order, which is observable.
//
// Registration order is what the operator-facing catalog and the generated rule reference list rules in. An order that varied by
// replica would make those surfaces disagree depending on which replica answered.
func TestCorpus_DocumentsAreOrderedByPath(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	// Inserted deliberately out of order.
	_, err := s.Replace(ctx, []api.Document{
		{Path: "imported/z.yml", Content: []byte("z")},
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/m.yml", Content: []byte("m")},
	})
	require.NoError(t, err)

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 3)
	assert.Equal(t, "imported/a.yml", docs[0].Path)
	assert.Equal(t, "imported/m.yml", docs[1].Path)
	assert.Equal(t, "imported/z.yml", docs[2].Path)
}

// TestCorpus_PathsAreBytewiseIdentities pins that a path is compared and ordered the way a filesystem does it.
//
// The table's default collation is case- and accent-insensitive, and a path is neither. Under the default, two documents whose
// paths differ only by case COLLIDE on the primary key, so a corpus holding both fails to store at all; because a replace is
// all-or-nothing that takes the whole corpus down to the embedded fallback, over a distinction the filesystem and the loader both
// consider meaningful. Ordering diverges for the same reason: the loader sorts bytewise, so a mixed-case corpus would load in a
// different order from storage than from the build, and registration order is observable.
//
// Latent today, because the vendored corpus is all lowercase. It stops being latent the moment an operator authors a rule (#767),
// which is a bad time to discover the corpus silently will not load.
func TestCorpus_PathsAreBytewiseIdentities(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	// Bytewise, uppercase sorts before lowercase, which an insensitive collation does not reproduce.
	_, err := s.Replace(ctx, []api.Document{
		{Path: "imported/case_test.yml", Content: []byte("lower")},
		{Path: "imported/Case_test.yml", Content: []byte("upper")},
		{Path: "imported/naive_rule.yml", Content: []byte("ascii")},
		{Path: "imported/na\u00efve_rule.yml", Content: []byte("accented")},
	})
	require.NoError(t, err, "paths differing only by case or accent are distinct files, so storing them must not collide")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 4, "all four are distinct identities")

	paths := make([]string, 0, len(docs))
	for _, d := range docs {
		paths = append(paths, d.Path)
	}
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	assert.Equal(t, sorted, paths,
		"storage must order paths exactly as Go does, since that is the order the loader builds the rule set in")

	byPath := map[string]string{}
	for _, d := range docs {
		byPath[d.Path] = string(d.Content)
	}
	assert.Equal(t, "lower", byPath["imported/case_test.yml"])
	assert.Equal(t, "upper", byPath["imported/Case_test.yml"], "and neither may overwrite the other")
}

// spec:rule-content/rule-content-is-stored-and-is-the-source-the-catalog-loads-from/the-version-is-readable-without-reading-the-content
//
// TestCorpus_VersionStartsSeeded covers the counter's initial state.
//
// Seeded by the migration so a reader never distinguishes "no counter row" from "version zero", which would otherwise be an error
// path every caller had to handle on a fresh deployment.
func TestCorpus_VersionStartsSeeded(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	version, err := s.Version(t.Context())
	require.NoError(t, err, "the counter row must exist on a fresh schema")
	assert.Zero(t, version)

	docs, err := s.Documents(t.Context())
	require.NoError(t, err)
	assert.Empty(t, docs, "and a fresh corpus is empty, which is what the seed's guard keys on")
}
