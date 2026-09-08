package eventlog

import (
	"bytes"
	"encoding/hex"
	"testing"

	"pgregory.net/rapid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBatchDigestIsInjective is the property the "exact batch" check rests on: two different sets of event ids must not digest
// alike, or one batch can be handed another's tally, which is the double count the digest exists to prevent.
//
// Property-based rather than table-driven because the failure is a COLLISION, which is a statement about a whole input space and
// not about any one pair. The pair review found is pinned separately below, because a named reproducer is worth having by name.
func TestBatchDigestIsInjective(t *testing.T) {
	t.Parallel()
	// Ids drawn from a tiny alphabet that INCLUDES the separator bytes a naive encoding would join on, since that is where
	// collisions live. A larger alphabet would make collisions vanishingly unlikely to be drawn and the property vacuous.
	id := rapid.Custom(func(t *rapid.T) string {
		parts := rapid.SliceOfN(rapid.SampledFrom([]string{"a", "b", "\x00", "|", ":"}), 0, 4).Draw(t, "parts")
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return string(b)
	})
	set := rapid.SliceOfNDistinct(id, 1, 4, func(s string) string { return s })

	rapid.Check(t, func(t *rapid.T) {
		left := set.Draw(t, "left")
		right := set.Draw(t, "right")

		sameSet := equalAsSets(left, right)
		sameDigest := bytes.Equal(batchDigest(left), batchDigest(right))
		if sameSet != sameDigest {
			t.Fatalf("digest disagrees with set equality: left=%q right=%q sameSet=%v sameDigest=%v",
				left, right, sameSet, sameDigest)
		}
	})
}

// equalAsSets compares two id lists ignoring order, which is what the digest is meant to reflect.
func equalAsSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, s := range left {
		counts[s]++
	}
	for _, s := range right {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

// TestBatchDigestSeparatorCollision is the exact pair review found against the first version, which joined ids on a NUL. Ingest
// rejects only an EMPTY event id, and the intake fuzz corpus seeds one containing a NUL deliberately, so this is a shape the
// system accepts rather than a contrived one.
func TestBatchDigestSeparatorCollision(t *testing.T) {
	t.Parallel()
	left := batchDigest([]string{"a", "b", "c\x00d"})
	right := batchDigest([]string{"a", "b\x00c", "d"})
	require.NotEqual(t, left, right,
		"these are different batches; digesting them alike lets one be handed the other's tally")

	// Order is not part of a batch's identity, which is the other half of what the digest has to get right.
	assert.Equal(t, batchDigest([]string{"z", "a", "m"}), batchDigest([]string{"m", "z", "a"}))
}

// TestBatchDigestGoldenValue pins the persisted digest FORMAT against literal bytes, which the tests above cannot do.
//
// They compare batchDigest to another call to batchDigest, so they hold under any change to the framing or the hash. That is right
// for the property they state and useless for the one that matters here: this value is WRITTEN to the queue by one build and
// compared against a LATER build's computation of it. Change the framing and every tally written before a rolling deploy stops
// matching, so the carry silently drops exactly the counts it exists to preserve, and not one self-comparing test fails. Review
// caught that, and it is the same shape as PackDigest's golden test (server/rulecontent/api/packdigest_test.go).
//
// The fixture is deliberately awkward: the ids are given OUT of sorted order, and one contains a NUL, so the value covers the sort
// and the length-prefixing rather than only the hash call.
func TestBatchDigestGoldenValue(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "b4973a27c253f874df2d5b474a54bd9cb76592fc11620a43539689117d107c5a",
		hex.EncodeToString(batchDigest([]string{"z-second", "a-first\x00with-nul", "m-third"})),
		"the persisted digest format changed, so tallies written by a build before this one would stop matching and be dropped")
}
