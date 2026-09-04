package sigma

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spec:server-detection-rules-engine/a-rule-s-pattern-cannot-make-matching-arbitrarily-expensive/a-pattern-with-an-unbounded-run-of-single-character-wildcards-is-refused
// spec:server-detection-rules-engine/a-rule-s-pattern-cannot-make-matching-arbitrarily-expensive/a-regular-expression-longer-than-the-limit-is-refused
//
// TestCompileValue_BoundsWhatAPatternCanCost covers the bounds that exist because #767 makes patterns operator-authored.
//
// Each case is at the boundary rather than far past it, so a limit changed by one is caught. The accepted rows matter as much as
// the refused ones: a bound that also refuses ordinary patterns is a worse outcome than no bound, because it pushes an author
// toward whatever expression slips through instead.
func TestCompileValue_BoundsWhatAPatternCanCost(t *testing.T) {
	t.Parallel()

	t.Run("single-character wildcards between stars", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name    string
			pattern string
			refused bool
		}{
			{
				name:    "at the limit",
				pattern: "*" + strings.Repeat("?", maxUnanchoredAnyRunes) + "x*",
			},
			{
				name:    "one past the limit",
				pattern: "*" + strings.Repeat("?", maxUnanchoredAnyRunes+1) + "x*",
				refused: true,
			},
			{
				// Anchored to the start, so it is checked once rather than at every offset, and costs nothing to allow.
				name:    "a long run in the FIRST segment is anchored and allowed",
				pattern: strings.Repeat("?", maxUnanchoredAnyRunes*4) + "x*",
			},
			{
				// Same reasoning at the other end.
				name:    "a long run in the LAST segment is anchored and allowed",
				pattern: "*x" + strings.Repeat("?", maxUnanchoredAnyRunes*4),
			},
			{
				// No stars at all: one segment, anchored at both ends, one comparison.
				name:    "a long run with no stars is one anchored segment",
				pattern: strings.Repeat("?", maxUnanchoredAnyRunes*4),
			},
			{
				name:    "the shapes real rules use",
				pattern: "*/usr/bin/??/tool*",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				_, err := compileValue(tc.pattern, nil, false)
				if tc.refused {
					require.ErrorIs(t, err, ErrUnsupported)
					assert.Contains(t, err.Error(), "single-character wildcards",
						"the refusal must say which part of the pattern to change")
					return
				}
				require.NoError(t, err)
			})
		}
	})

	t.Run("regular expression source length", func(t *testing.T) {
		t.Parallel()

		_, err := compileValue("a"+strings.Repeat("b", maxRegexpSource-1), nil, true)
		require.NoError(t, err, "a pattern at the limit must compile")

		_, err = compileValue("a"+strings.Repeat("b", maxRegexpSource), nil, true)
		require.ErrorIs(t, err, ErrUnsupported)
		assert.Contains(t, err.Error(), "regular expression")

		// The classic exponential-backtracking shape, allowed on purpose: Go's regexp is RE2, so it matches in linear time and
		// refusing it would be a defence against a threat this evaluator does not have.
		_, err = compileValue("(a+)+$", nil, true)
		require.NoError(t, err, "RE2 has no catastrophic case, so this pattern is ordinary here")
	})
}

// spec:server-detection-rules-engine/a-rule-s-pattern-cannot-make-matching-arbitrarily-expensive/a-field-testing-more-values-than-the-limit-is-refused
//
// TestFieldTest_BoundsHowManyValuesAFieldCarries covers the multiplier. Each value is tried until one matches, so a field listing
// thousands of patterns pays for every one of them on each event that does NOT match, which is almost all of them.
func TestFieldTest_BoundsHowManyValuesAFieldCarries(t *testing.T) {
	t.Parallel()

	values := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = "value"
		}
		return out
	}

	_, err := Compile(map[string]any{
		"selection": map[string]any{"Image": values(maxFieldValues)},
		"condition": "selection",
	})
	require.NoError(t, err, "a field at the limit must compile")

	_, err = Compile(map[string]any{
		"selection": map[string]any{"Image": values(maxFieldValues + 1)},
		"condition": "selection",
	})
	require.ErrorIs(t, err, ErrUnsupported)
	assert.Contains(t, err.Error(), "Image", "the refusal must name the field")
}
