package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// spec:rule-content/the-corpus-identifies-which-shipped-pack-it-holds/the-identity-is-stable-for-unchanged-content
// spec:rule-content/the-corpus-identifies-which-shipped-pack-it-holds/the-identity-changes-when-the-shipped-content-changes
func TestPackDigest(t *testing.T) {
	t.Parallel()
	base := []Document{
		{Path: "imported/a.yml", Content: []byte("alpha")},
		{Path: "imported/b.yml", Content: []byte("beta")},
	}

	t.Run("stable for the same content, and does not disturb its input", func(t *testing.T) {
		t.Parallel()
		// Asserted against a SEPARATELY CONSTRUCTED equal set rather than against the same expression twice. Hashing one value
		// twice is trivially equal unless the function keeps state, so it tests almost nothing; what is worth pinning is that two
		// callers holding equal content agree, which is the property a deployment comparing itself to a build depends on.
		same := []Document{
			{Path: "imported/a.yml", Content: []byte("alpha")},
			{Path: "imported/b.yml", Content: []byte("beta")},
		}
		assert.Equal(t, PackDigest(base), PackDigest(same))

		// And the order the caller handed them over in survives, because the function sorts a CLONE. A sort in place would
		// reorder a slice its caller still holds, which is the kind of side effect that surfaces somewhere else entirely.
		unsorted := []Document{base[1], base[0]}
		_ = PackDigest(unsorted)
		assert.Equal(t, "imported/b.yml", unsorted[0].Path, "the caller's slice must not be reordered under it")
	})

	t.Run("independent of the order it is given in", func(t *testing.T) {
		t.Parallel()
		// A caller assembling a pack from a filesystem walk does not necessarily hand them over sorted, and the digest is a
		// property of the SET rather than of the reading order.
		reversed := []Document{base[1], base[0]}
		assert.Equal(t, PackDigest(base), PackDigest(reversed))
	})

	t.Run("changes when content changes", func(t *testing.T) {
		t.Parallel()
		changed := []Document{base[0], {Path: "imported/b.yml", Content: []byte("beta!")}}
		assert.NotEqual(t, PackDigest(base), PackDigest(changed))
	})

	t.Run("changes when a document is added", func(t *testing.T) {
		t.Parallel()
		added := append(append([]Document{}, base...), Document{Path: "imported/c.yml", Content: []byte("gamma")})
		assert.NotEqual(t, PackDigest(base), PackDigest(added))
	})

	t.Run("changes when a document is removed", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, PackDigest(base), PackDigest(base[:1]))
	})

	t.Run("changes when a document MOVES without its content changing", func(t *testing.T) {
		t.Parallel()
		// The path is hashed, not only the bytes. Without that a rule could move between directories, changing which file the
		// loader reads it from, while the deployment still believed it held the same pack.
		//
		// The moved path is chosen to keep the SORT ORDER identical, and that is not incidental. An earlier version moved
		// "imported/a.yml" to "imported/moved.yml", which sorts after "imported/b.yml", so the contents changed order and the
		// digest differed for that reason instead. It asserted the right thing and would have passed with the path removed from
		// the hash entirely, which mutation testing is how I found out.
		moved := []Document{{Path: "imported/aa.yml", Content: []byte("alpha")}, base[1]}
		assert.Equal(t, [][]byte{[]byte("alpha"), []byte("beta")}, contentsInOrder(moved),
			"the fixture must differ from base ONLY in a path, or it tests ordering rather than path hashing")
		assert.NotEqual(t, PackDigest(base), PackDigest(moved))
	})

	t.Run("a split between path and content cannot collide", func(t *testing.T) {
		t.Parallel()
		// Without a length prefix these two hash the same concatenation, so a digest could be preserved across a change that
		// moves bytes from the path into the content. Unlikely by accident and cheap to rule out.
		a := []Document{{Path: "a", Content: []byte("bc")}}
		b := []Document{{Path: "ab", Content: []byte("c")}}
		assert.NotEqual(t, PackDigest(a), PackDigest(b))
	})

	t.Run("an empty pack has a stable identity of its own", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, PackDigest(nil), PackDigest([]Document{}))
		assert.NotEqual(t, PackDigest(nil), PackDigest(base))
	})
}

// spec:rule-content/the-corpus-identifies-which-shipped-pack-it-holds/content-written-by-an-operator-does-not-change-the-pack-identity
//
// TestVendoredDocuments_ExcludesAuthoredContent is what keeps an operator's own rules from making a deployment look out of date,
// and keeps deleting one from making it look current.
func TestVendoredDocuments_ExcludesAuthoredContent(t *testing.T) {
	t.Parallel()
	mixed := []Document{
		{Path: "imported/a.yml", Content: []byte("alpha"), Source: SourceVendored},
		{Path: "authored/mine.yml", Content: []byte("mine"), Source: SourceAuthored},
		{Path: "imported/b.yml", Content: []byte("beta"), Source: SourceVendored},
	}
	vendoredOnly := []Document{mixed[0], mixed[2]}

	assert.Equal(t, vendoredOnly, VendoredDocuments(mixed))
	assert.Equal(t, PackDigest(VendoredDocuments(vendoredOnly)), PackDigest(VendoredDocuments(mixed)),
		"adding a rule of their own must not change which pack the deployment is running")
}

// TestSource_ValidRejectsAnythingUnrecognised keeps a row written by a future version from being silently read as one of today's
// two values, which would attribute content on the strength of not understanding it.
func TestSource_ValidRejectsAnythingUnrecognised(t *testing.T) {
	t.Parallel()

	// Pinned as LITERALS, because these are stored values and every other assertion here compares a constant with itself. A
	// rename would pass all of them, and the damage is not theoretical now that an unrecognised source is REFUSED on read:
	// every row an earlier version wrote would stop being interpretable, so the whole corpus of every existing deployment would
	// fail to load. Changing either string is a migration, and this is where that has to be noticed.
	assert.Equal(t, "vendored", string(SourceVendored), "the stored value for content shipped with the product")
	assert.Equal(t, "authored", string(SourceAuthored), "the stored value for content an operator wrote")

	cases := []struct {
		name  string
		value Source
		valid bool
	}{
		{"content shipped with the product", SourceVendored, true},
		{"content an operator wrote", SourceAuthored, true},
		// Empty is what a caller supplies when it does not state a provenance. It is a supported INPUT, resolved to vendored
		// before storage, but it is never a stored value, so reading one back means something is wrong.
		{"unstated", "", false},
		// The path prefix the corpus happens to use. Named here because it is the value someone would reach for if they
		// reintroduced path-derived provenance, which is the design this change rules out.
		{"the storage prefix mistaken for a source", "imported", false},
		{"a plausible synonym", "operator", false},
		// Case matters: the column collates case-insensitively for lookups elsewhere in this schema, so a reader that folded
		// case would accept a value nothing writes.
		{"the right word in the wrong case", "VENDORED", false},
		{"a value a later version might introduce", "community", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.valid, tc.value.Valid(), "Valid() for %q", tc.value)
		})
	}
}

// contentsInOrder returns the contents a digest would hash, in digest order, so a fixture can assert it differs from another only
// in the way it means to.
func contentsInOrder(docs []Document) [][]byte {
	sorted := append([]Document{}, docs...)
	SortDocuments(sorted)
	out := make([][]byte, 0, len(sorted))
	for _, d := range sorted {
		out = append(out, d.Content)
	}
	return out
}

// TestPackDigest_GoldenValue pins the persisted digest FORMAT against literal bytes, which every other test here cannot do.
//
// The stability assertions elsewhere compare PackDigest to another call to PackDigest, so they hold under any change to the
// framing, the field order, or the hash itself. That is fine for the property they state and useless for the one that matters
// here: this value is written to the database and compared against a LATER build's computation of it. Change the framing and
// every deployment silently reads as not current, an upgrade nobody asked for is offered for a pack that never moved, and not
// one self-comparing test fails. Review caught that, and it is the same shape as the weak tests mutation testing found earlier.
//
// So this is a wire-format pin in the project's sense: literal expected bytes, auditable by reading. A change to the framing has
// to fail here, so that carrying deployments across it becomes a deliberate decision rather than a surprise.
//
// The fixture is deliberately awkward. The documents are given OUT of sorted order, and one path is a sibling of the other's
// directory, so the value covers the sort and the length-prefixing rather than only the hash call.
func TestPackDigest_GoldenValue(t *testing.T) {
	t.Parallel()

	docs := []Document{
		{Path: "imported/process_creation/b.yml", Content: []byte("title: B\n"), Source: SourceVendored},
		{Path: "imported/a.yml", Content: []byte("title: A\n"), Source: SourceVendored},
	}
	assert.Equal(t, "0998ff11c3a534c62b4cac91e60f506894756535a0efb4fe8d08b89dcca439f4", PackDigest(docs),
		"the persisted digest format changed, so deployments carrying the old value would all read as out of date")

	// An empty pack has its own identity, and it is the digest of no fields rather than a special case in the code. Worth
	// pinning because "" means UNKNOWN elsewhere, and the two must never be conflated: unknown is a corpus that predates the
	// digest, empty is a build that genuinely ships no rules.
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", PackDigest(nil),
		"the empty pack's identity is the digest of nothing, and is not the empty string")
}
