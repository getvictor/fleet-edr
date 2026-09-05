//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentmysql "github.com/fleetdm/edr/server/rulecontent/internal/mysql"
	rulecontenttestkit "github.com/fleetdm/edr/server/rulecontent/testkit"
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
// Driven through Replace with a MIXED set, which pins the whole-corpus writers' own filtering rather than the recomputation the
// single-document paths do. The two are worth separating: TestPackDigest_FollowsASingleDocumentMutation covers those.
//
// An earlier version of this test drove PutDocument, and proved nothing. At the time only the whole-corpus writers recorded a
// digest, so the recorded value was untouched whatever the filter did: it passed because nothing recomputed, not because
// authored content was excluded. Mutation testing is how that surfaced. PutDocument does recompute now, which is a fix that
// arrived later and would have masked the original gap rather than closing it.
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
// TestPackDigest_FollowsASingleDocumentMutation is the half the whole-corpus tests cannot reach, and review found it missing.
// Both single-document mutations can change the SHIPPED set without looking like they do: writing over a shipped document
// reclassifies that row as the operator's, and deleting one removes it. A digest only the whole-corpus writers maintained would
// keep asserting the deployment holds a pack it no longer holds, which is the single claim the digest exists to make.
//
// Driven from a table because the cases differ in exactly one expectation, whether the pack MOVED, and stating that in a column
// is what makes the third case load-bearing rather than decorative: an operator's own rule must not move it.
//
// Every case also has to satisfy an invariant no per-case assertion states, and it is the stronger of the two claims: whatever
// the mutation was, the recorded identity must equal the digest of the shipped content actually left behind. A digest that
// changed for the wrong reason would satisfy "it moved" and fail this.
func TestPackDigest_FollowsASingleDocumentMutation(t *testing.T) {
	t.Parallel()

	shipped := func(path, content string) api.Document {
		return api.Document{Path: path, Content: []byte(content), Source: api.SourceVendored}
	}
	seed := []api.Document{shipped("imported/a.yml", "a"), shipped("imported/b.yml", "b")}

	cases := []struct {
		name      string
		mutate    func(t *testing.T, s *rulecontentmysql.Store, version int64)
		packMoved bool
	}{
		{
			// The operator writes their own version of a shipped rule. It keeps the path, so the row becomes theirs and the
			// pack is one rule smaller.
			name: "overwriting a shipped document",
			mutate: func(t *testing.T, s *rulecontentmysql.Store, version int64) {
				_, err := s.PutDocument(t.Context(),
					api.Document{Path: "imported/a.yml", Content: []byte("mine")}, version)
				require.NoError(t, err)
			},
			packMoved: true,
		},
		{
			name: "deleting a shipped document",
			mutate: func(t *testing.T, s *rulecontentmysql.Store, version int64) {
				_, err := s.DeleteDocument(t.Context(), "imported/a.yml", version)
				require.NoError(t, err)
			},
			packMoved: true,
		},
		{
			// Adding their own rule must not make the deployment look out of date. This is what stops the recomputation above
			// from being "recompute on every write", which would be correct and needlessly expensive.
			name: "adding a rule of the operator's own",
			mutate: func(t *testing.T, s *rulecontentmysql.Store, version int64) {
				_, err := s.PutDocument(t.Context(),
					api.Document{Path: "authored/mine.yml", Content: []byte("mine")}, version)
				require.NoError(t, err)
			},
			packMoved: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newStore(t)
			ctx := t.Context()

			version, err := s.Replace(ctx, seed)
			require.NoError(t, err)
			before, err := s.PackDigest(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, before)

			tc.mutate(t, s, version)

			after, err := s.PackDigest(ctx)
			require.NoError(t, err)
			if tc.packMoved {
				assert.NotEqual(t, before, after, "the shipped content changed, so the pack identity must have moved")
			} else {
				assert.Equal(t, before, after, "the shipped content is unchanged, so the pack identity must be too")
			}

			stored, err := s.Documents(ctx)
			require.NoError(t, err)
			assert.Equal(t, api.PackDigest(api.VendoredDocuments(stored)), after,
				"the recorded identity must be the digest of the shipped content actually stored")
		})
	}
}

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

// spec:rule-content/the-corpus-identifies-which-shipped-pack-it-holds/a-corpus-stored-before-pack-identity-was-recorded-reports-none
//
// TestPackDigest_UnrecordedIsUnknownNotEmpty separates the two states that both look like "nothing" and mean opposite things.
//
// A corpus stored before this existed holds SOME generation of shipped content, and nothing wrote down which. Reporting a digest
// for it would be inventing one, and reporting the EMPTY pack's digest would be worse: that is a real identity, so the deployment
// would claim to hold no shipped rules while running a full corpus. The upgrade path reads the absence as "unknown, therefore not
// known to be current", and that only works if the two are distinguishable.
func TestPackDigest_UnrecordedIsUnknownNotEmpty(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	// A fresh corpus that nothing has written: the state the migration leaves a pre-existing deployment in.
	digest, err := s.PackDigest(ctx)
	require.NoError(t, err)
	assert.Empty(t, digest, "an unrecorded pack identity is absent, not computed")
	assert.NotEqual(t, api.PackDigest(nil), digest,
		"absent must be distinguishable from the identity of a genuinely empty pack, or unknown reads as current")
}

// TestProvenanceMigration_LeavesExistingDocumentsIntact runs the REAL migration against a corpus that already holds documents,
// which review pointed out nothing did: every other test here opens an already-migrated database, so the migration's behaviour on
// existing content was asserted only by the dev-server QA and by nothing repeatable.
//
// The claim under test is the one the migration's own comment makes: documents stored before provenance existed survive, and are
// recorded as having shipped with the product. That default is a statement of fact rather than a guess, since every document
// predating the migration was written by the seed, and it is the direction that fails safely: over-crediting upstream is visible,
// where the reverse silently drops a licence obligation.
//
// It rewinds by dropping the two columns and the migration's own version row, then re-applies the schema, so goose replays the
// checked-in file rather than a copy of its DDL restated here. A copy would drift from the migration it claims to cover.
func TestProvenanceMigration_LeavesExistingDocumentsIntact(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	s := rulecontentmysql.New(db)
	ctx := t.Context()

	_, err := s.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("title: A\n"), Source: api.SourceVendored},
		{Path: "imported/process_creation/b.yml", Content: []byte("title: B\n"), Source: api.SourceVendored},
	})
	require.NoError(t, err)

	// Rewind to the pre-migration shape: the columns gone, and goose no longer believing it has applied 00002.
	for _, stmt := range []string{
		"ALTER TABLE rule_corpus_documents DROP COLUMN source",
		"ALTER TABLE rule_corpus_meta DROP COLUMN pack_digest",
		"DELETE FROM rulecontent_goose_db_version WHERE version_id = 2",
	} {
		_, err := db.ExecContext(ctx, stmt)
		require.NoError(t, err, "rewind step %q", stmt)
	}

	require.NoError(t, rulecontenttestkit.ApplySchema(ctx, db), "the migration must apply to a populated corpus")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 2, "the migration must not remove documents it found")
	for _, d := range docs {
		assert.Equal(t, api.SourceVendored, d.Source,
			"%s predates provenance, so it came with the product", d.Path)
	}
	assert.Equal(t, "title: A\n", string(docs[0].Content), "content must survive the migration unchanged")

	// The pack identity is deliberately NOT invented for a corpus that predates it: this deployment holds some generation of
	// shipped content and nothing recorded which, so the upgrade path reads the absence as "unknown, therefore not current".
	digest, err := s.PackDigest(ctx)
	require.NoError(t, err)
	assert.Empty(t, digest, "a migrated corpus must not claim a pack identity nobody recorded")
}
