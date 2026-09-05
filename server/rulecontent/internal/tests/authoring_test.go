//go:build integration

package tests

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
)

// spec:rule-content/operators-author-rule-content/a-created-document-joins-the-corpus
//
// TestPutDocument_CreatesAndReplaces covers both halves of an upsert against a real MySQL, because the statement is the part that
// cannot be verified by reading it: MySQL 8.4 deprecates the VALUES() form of ON DUPLICATE KEY UPDATE, so the alias form is the
// one that has to actually run.
func TestPutDocument_CreatesAndReplaces(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	before, err := s.Version(ctx)
	require.NoError(t, err)

	created, err := s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("first")})
	require.NoError(t, err)
	assert.Greater(t, created, before, "a write moves the version, or a replica never learns to re-read")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "imported/a.yml", docs[0].Path)
	assert.Equal(t, "first", string(docs[0].Content))

	replaced, err := s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("second")})
	require.NoError(t, err)
	assert.Greater(t, replaced, created)

	docs, err = s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1, "replacing a path must not add a second row for it")
	assert.Equal(t, "second", string(docs[0].Content))
}

// TestPutDocument_LeavesOtherDocumentsAlone is the property that makes this per-document rather than a Replace of the whole
// corpus. Two operators editing different rules must not discard each other's work, which a read-modify-write of the corpus
// cannot promise.
func TestPutDocument_LeavesOtherDocumentsAlone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	_, err := s.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/b.yml", Content: []byte("b")},
	})
	require.NoError(t, err)

	_, err = s.PutDocument(ctx, api.Document{Path: "imported/b.yml", Content: []byte("b-edited")})
	require.NoError(t, err)

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 2)
	assert.Equal(t, "a", string(docs[0].Content), "editing b must not touch a")
	assert.Equal(t, "b-edited", string(docs[1].Content))
}

// spec:rule-content/operators-author-rule-content/a-deleted-document-leaves-the-corpus
func TestDeleteDocument_RemovesAndBumpsTheVersion(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	seeded, err := s.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/b.yml", Content: []byte("b")},
	})
	require.NoError(t, err)

	after, err := s.DeleteDocument(ctx, "imported/a.yml")
	require.NoError(t, err)
	assert.Greater(t, after, seeded)

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "imported/b.yml", docs[0].Path)
}

// spec:rule-content/operators-author-rule-content/deleting-what-is-not-there-is-reported
//
// TestDeleteDocument_NotFoundLeavesTheVersionAlone pins BOTH halves, and the version half is the one worth stating. A delete that
// matched nothing must not move the counter: every replica polls it, so a bump with no content change makes the whole fleet
// re-read the corpus to discover that nothing happened.
//
// The not-found report is the other half. An operator who mistypes a path would otherwise be told they deleted a rule.
func TestDeleteDocument_NotFoundLeavesTheVersionAlone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	seeded, err := s.Replace(ctx, []api.Document{{Path: "imported/a.yml", Content: []byte("a")}})
	require.NoError(t, err)

	_, err = s.DeleteDocument(ctx, "imported/never-existed.yml")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrDocumentNotFound), "callers branch on this, so it must be matchable with errors.Is")

	now, err := s.Version(ctx)
	require.NoError(t, err)
	assert.Equal(t, seeded, now, "a delete that removed nothing must not make every replica re-read the corpus")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Len(t, docs, 1, "and it must not have removed anything either")
}
