//go:build integration

package tests

import (
	"strings"
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

	created, err := s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("first")}, -1)
	require.NoError(t, err)
	assert.Greater(t, created, before, "a write moves the version, or a replica never learns to re-read")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "imported/a.yml", docs[0].Path)
	assert.Equal(t, "first", string(docs[0].Content))

	replaced, err := s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("second")}, -1)
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

	_, err = s.PutDocument(ctx, api.Document{Path: "imported/b.yml", Content: []byte("b-edited")}, -1)
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

	after, err := s.DeleteDocument(ctx, "imported/a.yml", -1)
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

	_, err = s.DeleteDocument(ctx, "imported/never-existed.yml", -1)
	require.Error(t, err)
	require.ErrorIs(t, err, api.ErrDocumentNotFound, "callers branch on this, so it must be matchable with errors.Is")

	now, err := s.Version(ctx)
	require.NoError(t, err)
	assert.Equal(t, seeded, now, "a delete that removed nothing must not make every replica re-read the corpus")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Len(t, docs, 1, "and it must not have removed anything either")
}

// spec:rule-content/operators-author-rule-content/a-failed-write-changes-nothing
//
// TestPutDocument_AFailedWriteLeavesTheVersionAlone pins that the version bump is inside the same transaction as the document
// write, and it matters because the bump happens FIRST. Every replica polls that counter, so a write that failed after moving it
// would send the whole fleet to re-read a corpus that had not changed, and would report a version no content corresponds to.
//
// The failure is forced with a path longer than the column holds, which is deterministic and needs no fault injection: the insert
// fails inside the open transaction, and the deferred rollback takes the bump with it.
func TestPutDocument_AFailedWriteLeavesTheVersionAlone(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	before, err := s.Version(ctx)
	require.NoError(t, err)

	_, err = s.PutDocument(ctx, api.Document{
		Path:    "imported/" + strings.Repeat("x", 300) + ".yml",
		Content: []byte("content"),
	}, -1)
	require.Error(t, err, "a path the column cannot hold must fail rather than silently truncate")

	after, err := s.Version(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "the version bump must roll back with the write it was made for")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Empty(t, docs, "and nothing may be stored")
}

// spec:rule-content/operators-author-rule-content/a-write-validated-against-a-corpus-that-has-since-moved-is-refused
//
// TestPutDocument_RefusesAStaleVersion is what makes whole-corpus validation hold under concurrency.
//
// Validation happens against a snapshot, and the write lands in a separate transaction. Without this check the two are a
// check-then-act: two operators adding documents whose file stems collide each validate against a corpus lacking the other, both
// pass, and the corpus that lands claims one rule identity twice. Every replica then refuses the whole thing.
//
// A stale expected version must therefore refuse, and must leave both the corpus and its counter exactly as they were.
func TestPutDocument_RefusesAStaleVersion(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	stale, err := s.Version(ctx)
	require.NoError(t, err)

	// Somebody else writes first, moving the corpus on.
	current, err := s.PutDocument(ctx, api.Document{Path: "imported/other.yml", Content: []byte("other")}, stale)
	require.NoError(t, err)
	require.Greater(t, current, stale)

	// Our write was validated against the version before that one.
	_, err = s.PutDocument(ctx, api.Document{Path: "imported/ours.yml", Content: []byte("ours")}, stale)
	require.Error(t, err)
	require.ErrorIs(t, err, api.ErrCorpusChanged, "the caller re-reads, re-validates and retries on this")

	after, err := s.Version(ctx)
	require.NoError(t, err)
	assert.Equal(t, current, after, "a refused write must not move the counter")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1, "and must not store anything")
	assert.Equal(t, "imported/other.yml", docs[0].Path)
}

// TestDeleteDocument_RefusesAStaleVersion is the same property for the other mutation. Deleting on a stale view is the more
// alarming half: the corpus you validated the removal against is not the one you are removing from.
func TestDeleteDocument_RefusesAStaleVersion(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	seeded, err := s.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/b.yml", Content: []byte("b")},
	})
	require.NoError(t, err)

	_, err = s.PutDocument(ctx, api.Document{Path: "imported/c.yml", Content: []byte("c")}, seeded)
	require.NoError(t, err)

	_, err = s.DeleteDocument(ctx, "imported/a.yml", seeded)
	require.ErrorIs(t, err, api.ErrCorpusChanged)

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Len(t, docs, 3, "nothing removed on a stale view")
}
