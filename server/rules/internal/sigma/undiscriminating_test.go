package sigma

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGlobMatchesAnyValue_ExactShapes pins the predicate against the shapes it must and must not accept, and the negative cases
// are the ones that matter: a warning that fires on a deliberate pattern gets ignored.
//
// Each expectation is cross-checked against match() below, so this cannot drift into asserting what I believed the compiler does
// rather than what it does.
func TestGlobMatchesAnyValue_ExactShapes(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		pattern string
		want    bool
		why     string
	}{
		"single star":   {"*", true, "two empty segments, so anything satisfies it"},
		"double star":   {"**", true, "adjacent stars collapse to the single-star shape"},
		"triple star":   {"***", true, "same collapse"},
		"empty":         {"", false, "ONE empty segment, which must account for every byte: matches only the empty string"},
		"one any":       {"?", false, "requires exactly one character"},
		"star any star": {"*?*", false, "requires at least one character"},
		"literal":       {"osascript", false, "matches that literal"},
		"prefix":        {"osa*", false, "anchors the start"},
		"suffix":        {"*script", false, "anchors the end"},
		"middle":        {"*osa*", false, "requires the run to appear"},
		"star then any": {"*?", false, "requires at least one character at the end"},
		"any then star": {"?*", false, "requires at least one character at the start"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := compileGlob(tc.pattern)
			assert.Equal(t, tc.want, g.matchesAnyValue(), "%s: %s", tc.pattern, tc.why)
		})
	}
}

// TestGlobMatchesAnyValue_AgreesWithMatch is the check that keeps the predicate honest.
//
// The predicate claims something ABOUT match, so asserting it against my reading of the compiler would only pin my reading. Here
// every pattern the predicate calls undiscriminating is run against a spread of values including the empty string, and must
// accept all of them; every pattern it does not must reject at least one.
func TestGlobMatchesAnyValue_AgreesWithMatch(t *testing.T) {
	t.Parallel()
	values := []string{"", "a", "osascript", "/usr/bin/osascript", "  ", "ÿ", "a very much longer value than the others"}
	for _, pattern := range []string{"*", "**", "", "?", "*?*", "osascript", "osa*", "*script", "*osa*", "*?", "?*"} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			g := compileGlob(pattern)
			matchedAll := true
			for _, v := range values {
				if !g.match(v) {
					matchedAll = false
					break
				}
			}
			assert.Equal(t, g.matchesAnyValue(), matchedAll,
				"pattern %q: the predicate and match must agree about whether everything matches", pattern)
		})
	}
}

// TestUndiscriminatingSearches_NamesTheOffender covers the composition, through Compile rather than by hand-building the structs,
// so it exercises the shapes an operator can actually write.
func TestUndiscriminatingSearches_NamesTheOffender(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		detection map[string]any
		want      []string
	}{
		"a wildcard field discriminates nothing": {
			detection: map[string]any{
				"selection": map[string]any{"Image": "*"},
				"condition": "selection",
			},
			want: []string{"selection"},
		},
		"a real predicate does not": {
			detection: map[string]any{
				"selection": map[string]any{"Image|endswith": "/osascript"},
				"condition": "selection",
			},
			want: nil,
		},
		"only the offending search is named": {
			detection: map[string]any{
				"selection": map[string]any{"Image|endswith": "/osascript"},
				"anything":  map[string]any{"CommandLine": "*"},
				"condition": "selection and anything",
			},
			want: []string{"anything"},
		},
		"one unrestrictive value in a list decides the default form": {
			detection: map[string]any{
				"selection": map[string]any{"Image": []any{"/bin/sh", "*"}},
				"condition": "selection",
			},
			want: []string{"selection"},
		},
		"a second field that narrows saves the alternative": {
			detection: map[string]any{
				"selection": map[string]any{"Image": "*", "CommandLine|contains": "curl"},
				"condition": "selection",
			},
			want: nil,
		},
		"an empty-value pattern is the narrowest, not the broadest": {
			detection: map[string]any{
				"selection": map[string]any{"CommandLine": ""},
				"condition": "selection",
			},
			want: nil,
		},
		"a field required absent is a real predicate": {
			detection: map[string]any{
				"selection": map[string]any{"CommandLine": nil},
				"condition": "selection",
			},
			want: nil,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r, err := Compile(tc.detection)
			require.NoError(t, err)
			assert.Equal(t, tc.want, r.UndiscriminatingSearches())
		})
	}
}

// TestUndiscriminatingSearches_AlternativesAreOrNotAnd pins the composition rule that is easiest to get backwards.
//
// A search's alternatives are Sigma's list-of-maps form and the search holds when ANY of them does, so one undiscriminating
// alternative decides the search: the others cannot narrow it, because they are not required to hold.
func TestUndiscriminatingSearches_AlternativesAreOrNotAnd(t *testing.T) {
	t.Parallel()
	r, err := Compile(map[string]any{
		"selection": []any{
			map[string]any{"Image|endswith": "/osascript"},
			map[string]any{"Image": "*"},
		},
		"condition": "selection",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"selection"}, r.UndiscriminatingSearches(),
		"one alternative matching everything makes the search match everything, whatever the others require")
}

// TestUndiscriminatingSearches_SaysNothingAboutRegexps pins the deliberate gap, so nobody later reads the absence of a warning on
// a `.*` rule as coverage.
func TestUndiscriminatingSearches_SaysNothingAboutRegexps(t *testing.T) {
	t.Parallel()
	r, err := Compile(map[string]any{
		"selection": map[string]any{"Image|re": ".*"},
		"condition": "selection",
	})
	require.NoError(t, err)
	assert.Empty(t, r.UndiscriminatingSearches(),
		"a regexp that does match everything is NOT reported: deciding that is a question about the regexp engine, and a "+
			"predicate answering it wrongly in the reassuring direction would be worse than one that does not answer")
}

// TestFieldTest_AbsentCarriesNoValues pins the invariant discriminatesNothing leans on instead of re-checking.
//
// compileFieldTest sets absent and returns before compiling any value, so an absent test always has zero values and the
// empty-list guard answers it. That made an explicit absent check a second condition that could not disagree with the first,
// which is dead code. Removing it is only safe while this holds, so it is pinned here: a change to compileFieldTest breaks this
// test rather than making the breadth predicate quietly call `Field: null` undiscriminating.
func TestFieldTest_AbsentCarriesNoValues(t *testing.T) {
	t.Parallel()
	r, err := Compile(map[string]any{
		"selection": map[string]any{"CommandLine": nil},
		"condition": "selection",
	})
	require.NoError(t, err)
	require.Len(t, r.searches, 1)
	require.Len(t, r.searches[0].alternatives, 1)
	require.Len(t, r.searches[0].alternatives[0], 1)

	ft := r.searches[0].alternatives[0][0]
	require.True(t, ft.absent, "the fixture must actually produce an absent test, or this pins nothing")
	assert.Empty(t, ft.tests, "an absent test must carry no values; discriminatesNothing relies on it")
	assert.False(t, ft.discriminatesNothing(), "and a field required absent is a real predicate")
}

// TestUndiscriminatingSearches_AllFormQuantifiesOverEveryValue covers the `|all` branch, which the default-form tests cannot
// reach and which a reader would plausibly "simplify" into the same loop.
//
// `|all` needs EVERY listed value to match, so one restrictive value is enough to make the field discriminate. The default form
// is the opposite: one unrestrictive value is enough to make it not. Collapsing the two would report a rule that is genuinely
// specific.
func TestUndiscriminatingSearches_AllFormQuantifiesOverEveryValue(t *testing.T) {
	t.Parallel()

	t.Run("one restrictive value makes the |all field discriminate", func(t *testing.T) {
		t.Parallel()
		r, err := Compile(map[string]any{
			"selection": map[string]any{"Image|all": []any{"*", "/bin/sh"}},
			"condition": "selection",
		})
		require.NoError(t, err)
		assert.Empty(t, r.UndiscriminatingSearches(),
			"every listed value must match, and /bin/sh restricts, so the field discriminates")
	})

	t.Run("all values unrestrictive makes the |all field undiscriminating", func(t *testing.T) {
		t.Parallel()
		r, err := Compile(map[string]any{
			"selection": map[string]any{"Image|all": []any{"*", "**"}},
			"condition": "selection",
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"selection"}, r.UndiscriminatingSearches(),
			"nothing in the list restricts anything, so every event carrying the field satisfies it")
	})
}

// spec:rule-content/a-rule-that-discriminates-nothing-is-warned-about/a-negated-match-everything-search-is-not-warned-about
// spec:rule-content/a-rule-that-discriminates-nothing-is-warned-about/a-search-the-condition-does-not-use-is-not-warned-about
//
// TestUndiscriminatingSearches_PolarityDecidesWhetherBreadthIsAFootGun covers the counterexample review produced against my own
// stated reasoning.
//
// I had documented that a search matching everything contributes nothing wherever it sits, and ignored the condition on that
// basis. It is false under negation: with `condition: not selection` and a wildcard selection, the rule matches exactly the
// events that have NO Image, so the wildcard is the rule's discriminating predicate. Reporting it would be a false positive of
// exactly the kind that teaches operators to ignore the warning, which is the failure this whole feature is built to avoid.
//
// The asymmetry is the point: always-true asserted contributes nothing; always-true NEGATED is always false, which is maximally
// discriminating and a different problem (a rule that can never fire) for someone else to report.
func TestUndiscriminatingSearches_PolarityDecidesWhetherBreadthIsAFootGun(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		detection map[string]any
		want      []string
		why       string
	}{
		"asserted wildcard is a foot-gun": {
			detection: map[string]any{
				"selection": map[string]any{"Image": "*"},
				"condition": "selection",
			},
			want: []string{"selection"},
			why:  "always true, asserted: the rule matches everything",
		},
		"negated wildcard is the predicate": {
			detection: map[string]any{
				"selection": map[string]any{"Image": "*"},
				"condition": "not selection",
			},
			want: nil,
			why:  "matches exactly the events with no Image, which is discriminating",
		},
		"wildcard filter under and-not is not breadth": {
			detection: map[string]any{
				"selection": map[string]any{"Image|endswith": "/osascript"},
				"filter":    map[string]any{"CommandLine": "*"},
				"condition": "selection and not filter",
			},
			want: nil,
			why:  "the filter suppresses everything, so the rule never fires: a different problem, not breadth",
		},
		"double negation is positive again": {
			detection: map[string]any{
				"selection": map[string]any{"Image": "*"},
				"condition": "not (not selection)",
			},
			want: []string{"selection"},
			why:  "two negations restore the assertion",
		},
		"asserted wildcard in an or makes the whole rule broad": {
			detection: map[string]any{
				"selection": map[string]any{"Image|endswith": "/osascript"},
				"anything":  map[string]any{"CommandLine": "*"},
				"condition": "selection or anything",
			},
			want: []string{"anything"},
			why:  "an always-true branch of an or matches everything",
		},
		"a search the condition never mentions cannot make the rule broad": {
			detection: map[string]any{
				"selection": map[string]any{"Image|endswith": "/osascript"},
				"unused":    map[string]any{"CommandLine": "*"},
				"condition": "selection",
			},
			want: nil,
			why:  "an unreferenced search is never evaluated",
		},
		"a NEGATED quantifier does not make its members breadth": {
			detection: map[string]any{
				"selection_a": map[string]any{"Image|endswith": "/osascript"},
				"selection_b": map[string]any{"CommandLine": "*"},
				"condition":   "not 1 of selection_*",
			},
			want: nil,
			why:  "polarity has to pass through a quantifier too, or a negated always-true member reads as a foot-gun",
		},
		"a quantifier references its searches positively": {
			detection: map[string]any{
				"selection_a": map[string]any{"Image|endswith": "/osascript"},
				"selection_b": map[string]any{"CommandLine": "*"},
				"condition":   "1 of selection_*",
			},
			want: []string{"selection_b"},
			why:  "`1 of` is an or over its searches, so an always-true member matches everything",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r, err := Compile(tc.detection)
			require.NoError(t, err)
			assert.Equal(t, tc.want, r.UndiscriminatingSearches(), tc.why)
		})
	}
}

// TestUndiscriminatingSearches_OrderIsLexicalNotAuthored pins the ordering the doc comment claims, because the previous comment
// claimed declaration order and was wrong: Compile sorts the names, and it must, since a YAML mapping has no order to preserve.
//
// Worth a test rather than a corrected sentence, because "the same rule reports the same list every time" is the property a
// caller actually depends on, and a sentence cannot fail.
func TestUndiscriminatingSearches_OrderIsLexicalNotAuthored(t *testing.T) {
	t.Parallel()
	r, err := Compile(map[string]any{
		"zebra":     map[string]any{"Image": "*"},
		"alpha":     map[string]any{"CommandLine": "*"},
		"condition": "zebra or alpha",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "zebra"}, r.UndiscriminatingSearches(),
		"lexical by search name, whatever order the author wrote them in")
}
