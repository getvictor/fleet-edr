//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentmysql "github.com/fleetdm/edr/server/rulecontent/internal/mysql"
	"github.com/fleetdm/edr/server/testdb/full"
)

// spec:rule-content/a-rule-document-records-where-it-came-from/a-seeded-document-is-recorded-as-shipped-with-the-product
//
// TestSeed_RecordsDocumentsAsShippedWithTheProduct pins the provenance the whole of #874's fix rests on. The seed writes content
// that came with the build, so the corpus has to say so: an operator's rule is told apart from a shipped one by this and nothing
// else, since #873 established that a rule's identity is its file stem rather than its path.
func TestSeed_RecordsDocumentsAsShippedWithTheProduct(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	seeded, _, err := s.ReplaceIfEmpty(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/b.yml", Content: []byte("b")},
	})
	require.NoError(t, err)
	require.True(t, seeded)

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 2)
	for _, d := range docs {
		assert.Equal(t, api.SourceVendored, d.Source, "%s came with the product", d.Path)
	}
}

// spec:rule-content/a-rule-document-records-where-it-came-from/an-authored-document-is-recorded-as-the-operator-s
//
// TestPutDocument_RecordsTheDocumentAsTheOperators covers the path that matters most, and the fixture uses an `imported/` path
// DELIBERATELY. That is the laundering case: if provenance were read off the path, an operator writing there would turn their own
// rule into a vendored one and take a Detection Rule License attribution with it.
func TestPutDocument_RecordsTheDocumentAsTheOperators(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	base, err := s.Version(ctx)
	require.NoError(t, err)
	_, err = s.PutDocument(ctx, api.Document{Path: "imported/looks_vendored.yml", Content: []byte("mine")}, base)
	require.NoError(t, err)

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, api.SourceAuthored, docs[0].Source,
		"a document written through the authoring surface is the operator's, whatever path they chose")
}

// spec:rule-content/a-rule-document-records-where-it-came-from/replacing-a-shipped-document-with-an-authored-one-changes-its-provenance
//
// TestPutDocument_OverwritingAShippedDocumentMakesItTheOperators pins that provenance follows the CONTENT rather than the path's
// history. Once an operator has written over a shipped rule, the bytes are theirs, and crediting upstream for what they wrote is
// the same false claim in a subtler place.
func TestPutDocument_OverwritingAShippedDocumentMakesItTheOperators(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	seeded, version, err := s.ReplaceIfEmpty(ctx, []api.Document{{Path: "imported/a.yml", Content: []byte("shipped")}})
	require.NoError(t, err)
	require.True(t, seeded)

	_, err = s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("edited by me")}, version)
	require.NoError(t, err)

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, api.SourceAuthored, docs[0].Source)
	assert.Equal(t, "edited by me", string(docs[0].Content))
}

// TestPackDigest_CoversOnlyShippedContent is what stops an operator's own rules making a deployment look out of date, and stops
// deleting one making it look current. The pack is what shipped; their rules are not part of it.
//
// Driven through Replace with a MIXED set rather than through PutDocument, and the distinction is why an earlier version of this
// test proved nothing. Only the whole-corpus writers record a digest, so adding an authored document through PutDocument leaves
// the recorded value untouched whatever the filter does: the test passed because nothing recomputed, not because authored content
// was excluded. Mutation testing is how that surfaced.
func TestPackDigest_CoversOnlyShippedContent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	vendored := []api.Document{
		{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
		{Path: "imported/b.yml", Content: []byte("b"), Source: api.SourceVendored},
	}
	_, err := s.Replace(ctx, vendored)
	require.NoError(t, err)
	vendoredOnly, err := s.PackDigest(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, vendoredOnly)

	// The same shipped content, now alongside a rule the operator wrote.
	mixed := append(append([]api.Document{}, vendored...),
		api.Document{Path: "authored/mine.yml", Content: []byte("mine"), Source: api.SourceAuthored})
	_, err = s.Replace(ctx, mixed)
	require.NoError(t, err)
	withAuthored, err := s.PackDigest(ctx)
	require.NoError(t, err)

	assert.Equal(t, vendoredOnly, withAuthored,
		"the shipped content is unchanged, so the pack identity must be too")

	// And the corpus really did grow, so the fixture is not silently a no-op.
	stored, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, stored, 3, "the mixed replace must actually have stored the authored document")
}

// TestPackDigest_MatchesTheDigestOfWhatWasStored keeps the recorded identity honest about the content beside it. An identity
// recorded from the caller's un-defaulted view rather than from what was actually stored would report an empty pack for a full
// corpus, and the disagreement would be silent.
func TestPackDigest_MatchesTheDigestOfWhatWasStored(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	// No Source set, exactly as the seed hands them over.
	docs := []api.Document{
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/b.yml", Content: []byte("b")},
	}
	seeded, _, err := s.ReplaceIfEmpty(ctx, docs)
	require.NoError(t, err)
	require.True(t, seeded)

	recorded, err := s.PackDigest(ctx)
	require.NoError(t, err)

	stored, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Equal(t, api.PackDigest(api.VendoredDocuments(stored)), recorded,
		"the recorded identity must be the digest of the vendored content actually stored")
}

// spec:rule-content/the-corpus-identifies-which-shipped-pack-it-holds/changing-a-shipped-rule-changes-the-pack-identity
//
// TestPackDigest_FollowsASingleDocumentMutation is the half the whole-corpus tests above cannot reach, and review found it
// missing. Both single-document mutations can change the VENDORED set without looking like they do: writing over a shipped
// document reclassifies that row as the operator's, and deleting one removes it. A digest that only the whole-corpus writers
// maintain would keep asserting the deployment holds a pack it no longer holds, which is the single claim the digest exists to
// make.
func TestPackDigest_FollowsASingleDocumentMutation(t *testing.T) {
	t.Parallel()

	t.Run("overwriting a shipped document changes the pack", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		ctx := t.Context()

		version, err := s.Replace(ctx, []api.Document{
			{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
			{Path: "imported/b.yml", Content: []byte("b"), Source: api.SourceVendored},
		})
		require.NoError(t, err)
		before, err := s.PackDigest(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, before)

		// The operator writes their own version of a shipped rule. The row becomes theirs, so the pack is now one rule smaller.
		_, err = s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("mine")}, version)
		require.NoError(t, err)

		after, err := s.PackDigest(ctx)
		require.NoError(t, err)
		assert.NotEqual(t, before, after, "the shipped set lost a document, so the pack identity must have moved")

		stored, err := s.Documents(ctx)
		require.NoError(t, err)
		assert.Equal(t, api.PackDigest(api.VendoredDocuments(stored)), after,
			"the recorded identity must be the digest of the shipped content actually left")
	})

	t.Run("deleting a shipped document changes the pack", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		ctx := t.Context()

		version, err := s.Replace(ctx, []api.Document{
			{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
			{Path: "imported/b.yml", Content: []byte("b"), Source: api.SourceVendored},
		})
		require.NoError(t, err)
		before, err := s.PackDigest(ctx)
		require.NoError(t, err)

		_, err = s.DeleteDocument(ctx, "imported/a.yml", version)
		require.NoError(t, err)

		after, err := s.PackDigest(ctx)
		require.NoError(t, err)
		assert.NotEqual(t, before, after, "a shipped rule was removed, so the deployment no longer holds that pack")
	})

	t.Run("a purely authored change leaves the pack alone", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		ctx := t.Context()

		version, err := s.Replace(ctx, []api.Document{
			{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
		})
		require.NoError(t, err)
		before, err := s.PackDigest(ctx)
		require.NoError(t, err)

		// Adding their own rule must not make the deployment look out of date. This is the counterpart to the two cases above:
		// recomputing on every mutation is only correct if it still reports the same pack when the shipped half did not move.
		_, err = s.PutDocument(ctx, api.Document{Path: "authored/mine.yml", Content: []byte("mine")}, version)
		require.NoError(t, err)

		after, err := s.PackDigest(ctx)
		require.NoError(t, err)
		assert.Equal(t, before, after, "the operator's own rule is not part of the pack")
	})
}

// spec:rule-content/an-unrecognised-provenance-is-refused/content-declaring-an-unrecognised-provenance-is-not-stored
// spec:rule-content/an-unrecognised-provenance-is-refused/a-stored-document-with-an-unrecognised-provenance-is-not-interpreted
//
// TestUnknownSource_IsRefused covers the asymmetry that makes an unrecognised provenance value worse than either known one: it is
// not SourceAuthored, so attribution credits it upstream, and it is not SourceVendored, so the pack digest leaves it out. One
// such row would therefore carry a licence claim about content nothing here can vouch for, which is the failure this change
// exists to prevent. `Source.Valid` existed and said so in its own comment; nothing called it until review counted the callers.
func TestUnknownSource_IsRefused(t *testing.T) {
	t.Parallel()

	t.Run("on the way in, before anything is stored", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		ctx := t.Context()

		_, err := s.Replace(ctx, []api.Document{
			{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
		})
		require.NoError(t, err)

		_, err = s.Replace(ctx, []api.Document{
			{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
			{Path: "imported/b.yml", Content: []byte("b"), Source: api.Source("community")},
		})
		require.ErrorIs(t, err, api.ErrUnknownSource)

		// Refused WHOLE: the corpus must be exactly what it was, since a partly applied replacement is a state no reader
		// should be able to observe.
		stored, err := s.Documents(ctx)
		require.NoError(t, err)
		assert.Len(t, stored, 1, "a refused replacement must not have changed the corpus")
	})

	t.Run("on the way out, for a row this version cannot interpret", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		s := rulecontentmysql.New(db)
		ctx := t.Context()

		_, err := s.Replace(ctx, []api.Document{
			{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
		})
		require.NoError(t, err)

		// Written past the store, standing in for a row a future version wrote or a hand edit produced. The read has to refuse
		// it rather than fall through to crediting upstream.
		_, err = db.ExecContext(ctx, "UPDATE rule_corpus_documents SET source = ? WHERE path = ?", "community", "imported/a.yml")
		require.NoError(t, err)

		_, err = s.Documents(ctx)
		require.ErrorIs(t, err, api.ErrUnknownSource)
	})
}
