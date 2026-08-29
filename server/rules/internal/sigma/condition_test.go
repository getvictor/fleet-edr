package sigma

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// conditionRule builds a rule whose searches are single-field equality tests, so a condition can be exercised against a truth
// table without the field matching getting in the way.
func conditionRule(t *testing.T, condition string, names ...string) *Rule {
	t.Helper()
	detection := map[string]any{"condition": condition}
	for _, n := range names {
		detection[n] = map[string]any{n: "yes"}
	}
	r, err := Compile(detection)
	require.NoError(t, err)
	return r
}

// truth builds an event in which exactly the named searches match.
func truth(names ...string) mapEvent {
	ev := mapEvent{}
	for _, n := range names {
		ev[n] = []string{"yes"}
	}
	return ev
}

// TestCondition_Evaluates walks the operators and their precedence. The precedence cases carry the weight: `a or b and c` parsed
// left to right instead of by precedence still satisfies every single-operator test above it.
func TestCondition_Evaluates(t *testing.T) {
	t.Parallel()

	abc := []string{"a", "b", "c"}
	globs := []string{"s1", "s2"}
	corpus := []string{"selection", "filter_a", "filter_b"}

	cases := []struct {
		name      string
		condition string
		names     []string // the searches the rule declares
		matching  []string // of those, the ones this event satisfies
		want      bool
	}{
		{"bare identifier, matching", "a", abc, []string{"a"}, true},
		{"bare identifier, not matching", "a", abc, nil, false},

		{"and, both", "a and b", abc, []string{"a", "b"}, true},
		{"and, one", "a and b", abc, []string{"a"}, false},
		{"or, one", "a or b", abc, []string{"b"}, true},
		{"or, neither", "a or b", abc, nil, false},
		{"not, suppresses", "a and not b", abc, []string{"a", "b"}, false},
		{"not, admits", "a and not b", abc, []string{"a"}, true},
		{"double negation", "not not a", abc, []string{"a"}, true},

		// and binds tighter than or: true here only because `a` is true, since `b and c` is false.
		{"precedence: and binds tighter than or", "a or b and c", abc, []string{"a"}, true},
		{"precedence: and binds tighter than or, negative", "a or b and c", abc, []string{"b"}, false},
		{"parentheses override precedence", "(a or b) and c", abc, []string{"b", "c"}, true},
		{"parentheses, unsatisfied", "(a or b) and c", abc, []string{"b"}, false},
		{"not applies to a parenthesised group", "not (a or b)", abc, []string{"c"}, true},

		{"1 of glob, one matches", "1 of s*", globs, []string{"s1"}, true},
		{"1 of glob, none match", "1 of s*", globs, nil, false},
		{"all of glob, all match", "all of s*", globs, []string{"s1", "s2"}, true},
		{"all of glob, one missing", "all of s*", globs, []string{"s1"}, false},
		{"1 of them", "1 of them", globs, []string{"s2"}, true},
		{"all of them, one missing", "all of them", globs, []string{"s1"}, false},
		{"all of them, all present", "all of them", globs, []string{"s1", "s2"}, true},

		// The most common real shape in the corpus (191 rules): a selection minus a filter set.
		{"corpus shape: selection and not 1 of filter_*", "selection and not 1 of filter_*", corpus, []string{"selection"}, true},
		{"corpus shape: a filter suppresses", "selection and not 1 of filter_*", corpus, []string{"selection", "filter_a"}, false},

		{"operators are case-insensitive", "a AND NOT b", abc, []string{"a"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := conditionRule(t, tc.condition, tc.names...)
			assert.Equal(t, tc.want, r.Matches(truth(tc.matching...)))
		})
	}
}

// spec:server-detection-rules-engine/an-unsupported-or-meaningless-rule-construct-is-refused-when-the-rule-is-loaded/a-condition-naming-an-undefined-search-is-refused
//
// spec:server-detection-rules-engine/an-unsupported-or-meaningless-rule-construct-is-refused-when-the-rule-is-loaded/a-quantifier-matching-no-search-is-refused
//
// TestCondition_Rejects covers the parse-time refusals. The undefined-search case is the important one: left to evaluate, it is
// simply always false, so the rule loads clean and then detects nothing forever.
func TestCondition_Rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		condition string
		want      string
	}{
		{"undefined search", "a and zzz", "undefined search"},
		{"glob matching nothing", "1 of zzz_*", "matches no search identifier"},
		{"unclosed parenthesis", "(a and b", "unclosed parenthesis"},
		{"stray close parenthesis", "a )", "unexpected trailing"},
		{"empty condition", "", "unexpected end of condition"},
		{"dangling operator", "a and", "unexpected end of condition"},
		{"dangling not", "not", "unexpected end of condition"},
		{"of with no pattern", "1 of", "`of` with no pattern"},
		{"leading close paren", ")", "unexpected )"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(map[string]any{
				"condition": tc.condition,
				"a":         map[string]any{"a": "yes"},
				"b":         map[string]any{"b": "yes"},
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestCondition_AllNamedSearchIsNotAQuantifier guards the one genuine ambiguity in the grammar: `all` is a keyword in `all of x`
// but a legal search name on its own.
func TestCondition_AllNamedSearchIsNotAQuantifier(t *testing.T) {
	t.Parallel()

	r, err := Compile(map[string]any{
		"condition": "all",
		"all":       map[string]any{"all": "yes"},
	})
	require.NoError(t, err)
	assert.True(t, r.Matches(mapEvent{"all": {"yes"}}))
	assert.False(t, r.Matches(mapEvent{"all": {"no"}}))
}
