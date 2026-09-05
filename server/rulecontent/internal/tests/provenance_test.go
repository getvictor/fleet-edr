//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
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
