package sigma

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detectionWith wraps one field's values in the smallest detection Compile accepts, so these tests exercise the rule-level entry
// point rather than the value compiler underneath it. The scenarios promise a refusal that names the FIELD, and only this path can
// keep that promise.
func detectionWith(field string, values any) map[string]any {
	return map[string]any{
		"selection": map[string]any{field: values},
		"condition": "selection",
	}
}

// spec:server-detection-rules-engine/a-rule-s-pattern-cannot-make-matching-arbitrarily-expensive/a-pattern-costing-more-than-the-limit-is-refused
//
// TestCompile_BoundsWhatOnePatternCanCost covers the per-value half of the bound.
//
// The unit is the length of a segment with a star on either side, because that is the segment searched for at every candidate
// offset. Measured on a 4096-byte value at about 1.4us per atom, and measured for BOTH shapes: 1024 literal characters cost 1.41ms
// and 1024 `?` cost 4.10ms. An earlier version of this bound counted only the `?`, which left the literal half of the same cost
// wide open; review caught it and the table below now pins both.
func TestCompile_BoundsWhatOnePatternCanCost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
		refused bool
	}{
		{
			name:    "single-character wildcards at the limit",
			pattern: "*" + strings.Repeat("?", maxValueCost) + "*",
		},
		{
			name:    "single-character wildcards one past the limit",
			pattern: "*" + strings.Repeat("?", maxValueCost+1) + "*",
			refused: true,
		},
		{
			name:    "a literal run costs the same and is bounded the same",
			pattern: "*" + strings.Repeat("a", maxValueCost+1) + "*",
			refused: true,
		},
		{
			// Anchored to the start of the value, so it is compared once rather than searched for at every offset.
			name:    "a long run in the FIRST segment is anchored and costs nothing",
			pattern: strings.Repeat("a", maxValueCost*2) + "*",
		},
		{
			name:    "a long run in the LAST segment is anchored and costs nothing",
			pattern: "*" + strings.Repeat("a", maxValueCost*2),
		},
		{
			name:    "no stars at all is one anchored segment",
			pattern: strings.Repeat("a", maxValueCost*2),
		},
		{
			name:    "the shapes real rules use",
			pattern: "*/usr/bin/??/tool*",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(detectionWith("Image", tc.pattern))
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrUnsupported)
			assert.Contains(t, err.Error(), "Image", "the refusal must name the field so an author knows what to change")
			assert.Contains(t, err.Error(), strconv.Itoa(maxValueCost), "and the limit, so they know what to change it to")
		})
	}
}

// spec:server-detection-rules-engine/a-rule-s-pattern-cannot-make-matching-arbitrarily-expensive/a-field-costing-more-than-the-limit-across-its-values-is-refused
//
// TestCompile_BoundsWhatOneFieldCanCostAcrossItsValues covers the half that independent per-value limits cannot.
//
// A field's values are tried until one matches, so an event matching NONE of them pays for every one. Review measured the gap this
// closes: 512 individually legal values on one field cost 100ms per event, while each value passed its own limit comfortably.
func TestCompile_BoundsWhatOneFieldCanCostAcrossItsValues(t *testing.T) {
	t.Parallel()

	// Each value is a middle segment of 512, so it is well inside the per-value limit and the sum is what decides.
	const per = 512
	value := "*" + strings.Repeat("a", per) + "*"
	list := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = value
		}
		return out
	}

	t.Run("a field at the limit compiles", func(t *testing.T) {
		t.Parallel()
		_, err := Compile(detectionWith("Image", list(maxFieldCost/per)))
		require.NoError(t, err)
	})

	t.Run("a field one value past the limit is refused, naming the field", func(t *testing.T) {
		t.Parallel()
		_, err := Compile(detectionWith("Image", list(maxFieldCost/per+1)))
		require.ErrorIs(t, err, ErrUnsupported)
		assert.Contains(t, err.Error(), "Image")
		assert.Contains(t, err.Error(), "across its values", "the refusal must say it is the total, not one value")
	})

	t.Run("many CHEAP values are not refused, because the sum is what matters", func(t *testing.T) {
		t.Parallel()
		plain := make([]any, 4096)
		for i := range plain {
			plain[i] = "/usr/bin/tool"
		}
		_, err := Compile(detectionWith("Image", plain))
		require.NoError(t, err, "a long list of literals costs nothing per event and must stay legal")
	})
}

// spec:server-detection-rules-engine/a-rule-s-pattern-cannot-make-matching-arbitrarily-expensive/a-pattern-costing-more-than-the-limit-is-refused
//
// TestCompile_RegexpIsBoundedByItsCompiledProgram pins the unit for `|re`, which is not the source length.
//
// `a{1000}` is seven bytes and costs 2.19ms per match, because counted repetition expands when Go compiles it. Bounding the source
// would therefore have let the most expensive shape straight through, which is what the first version of this bound did.
func TestCompile_RegexpIsBoundedByItsCompiledProgram(t *testing.T) {
	t.Parallel()

	t.Run("a short source that expands past the limit is refused BY THIS BOUND", func(t *testing.T) {
		t.Parallel()
		// 12 source bytes, 6002 instructions. Go accepts it, so this is refused by the cost bound and by nothing else, which is
		// what makes it the case that distinguishes program size from source length. Mutation testing found the first version of
		// this test asserting only `require.Error` on a pattern Go's own parser refuses, so it passed with the bound removed.
		_, err := Compile(detectionWith("Image|re", "(abcd){1000}"))
		require.ErrorIs(t, err, ErrUnsupported)
		assert.Contains(t, err.Error(), "instructions", "the refusal must name the unit, since the source looks tiny")
		assert.Contains(t, err.Error(), "Image")
	})

	t.Run("nested repetition is refused by Go's parser, before this bound sees it", func(t *testing.T) {
		t.Parallel()
		_, err := Compile(detectionWith("Image|re", fmt.Sprintf("(a{%d}){%d}", 1000, 1000)))
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrUnsupported,
			"recorded deliberately: this shape needs no bound of ours, and asserting otherwise would credit this bound for Go's work")
	})

	t.Run("the classic backtracking shape is accepted, because RE2 has no such case", func(t *testing.T) {
		t.Parallel()
		_, err := Compile(detectionWith("Image|re", "(a+)+$"))
		require.NoError(t, err, "refusing this would defend against a threat this evaluator does not have")
	})

	t.Run("an ordinary expression is accepted", func(t *testing.T) {
		t.Parallel()
		_, err := Compile(detectionWith("Image|re", `([0-9]|[1-9][0-9]|[1-4][0-9]{2})`))
		require.NoError(t, err, "the longest expression the vendored corpus uses: 32 source bytes, 12 instructions")
	})
}

// TestCompileGlob_CollapsesAdjacentStars pins the fix for a cost that needed no limit.
//
// `**` matches exactly what `*` matches, so every extra star used to add an empty middle segment that the search walked for every
// value: 19ns at two stars, 40us at 8192, growing linearly in a pattern an author is free to write. Collapsing removes the growth
// instead of refusing the pattern, which is the better trade for something that means nothing unusual.
func TestCompileGlob_CollapsesAdjacentStars(t *testing.T) {
	t.Parallel()

	assert.Len(t, compileGlob("**").segs, len(compileGlob("*").segs),
		"two stars must compile to what one star compiles to")
	assert.Len(t, compileGlob(strings.Repeat("*", 8192)).segs, 2,
		"any run of stars is one star: a leading empty segment and a trailing one")

	// Matching is unchanged, which is the property that matters more than the segment count.
	for _, value := range []string{"", "a", "abc", strings.Repeat("a", 4096)} {
		assert.Equal(t, compileGlob("*").match(value), compileGlob("****").match(value), "value %q", value)
		assert.Equal(t, compileGlob("*a*").match(value), compileGlob("**a**").match(value), "value %q", value)
	}
}
