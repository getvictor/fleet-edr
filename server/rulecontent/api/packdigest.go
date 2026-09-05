package api

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
)

// PackDigest identifies a set of shipped rule documents by their content.
//
// Derived rather than declared, which is the point. A hand-maintained pack version has to be bumped by whoever edits the corpus,
// and forgetting is SILENT: the deployment believes it is current while running different rules, and nothing anywhere disagrees.
// A digest cannot be forgotten, because it is a function of the thing it describes.
//
// It answers one question: is the vendored content stored here the vendored content in this build. That makes "an upgrade is
// available" a comparison rather than a judgement, and it makes the answer survive a rebuild, a rollback, and a re-seed.
//
// Both the path and the content are hashed, and a length prefix separates them. Hashing the concatenation alone would let a
// document move between paths without changing the digest, and would let two different splits of the same bytes collide: a
// document at "a" holding "bc" would hash identically to one at "ab" holding "c". Neither is likely by accident, and both are
// cheap to rule out.
//
// The input is SORTED by path first, so the digest is a property of the SET rather than of the order it happened to be read in.
// Storage returns documents ordered, but a caller assembling a pack from a filesystem walk does not necessarily.
//
// AUTHORED documents are excluded by the caller, not here: this function digests exactly what it is given. What makes the digest
// stable across an operator adding their own rules is that callers pass the vendored subset, which is a decision worth keeping
// visible at the call site rather than buried in a hash function.
func PackDigest(docs []Document) string {
	sorted := slices.Clone(docs)
	SortDocuments(sorted)

	h := sha256.New()
	var lengthPrefix [8]byte
	writeField := func(b []byte) {
		binary.BigEndian.PutUint64(lengthPrefix[:], uint64(len(b)))
		// Hash writes never error (see the hash.Hash contract), so there is nothing here to handle.
		_, _ = h.Write(lengthPrefix[:])
		_, _ = h.Write(b)
	}
	for _, d := range sorted {
		writeField([]byte(d.Path))
		writeField(d.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VendoredDocuments returns just the documents shipped with the product.
//
// The counterpart to PackDigest, and separate from it so the choice of what counts as "the pack" is visible where it is made. An
// operator's own rules are not part of the pack: adding one must not make a deployment look out of date, and removing one must
// not make it look current.
func VendoredDocuments(docs []Document) []Document {
	out := make([]Document, 0, len(docs))
	for _, d := range docs {
		if d.Source == SourceVendored {
			out = append(out, d)
		}
	}
	return out
}
