package sigma

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapEvent is the literal-value Event the evaluator is tested against. Keeping the test surface independent of our payload
// shapes is the point of the Event interface: this package is about Sigma semantics, and the binding to our events is #761.
type mapEvent map[string][]string

func (m mapEvent) Field(name string) ([]string, bool) {
	v, ok := m[name]
	return v, ok
}

// spec:server-detection-rules-engine/rules-written-in-the-sigma-format-are-evaluated-against-a-single-event/values-are-compared-without-regard-to-case
//
// TestFieldTest_Modifiers is the per-modifier table the issue calls for, negatives included. Each modifier is checked for what it
// must match AND what it must not: `endswith` that also matched a prefix would pass any test that only asserted the positive.
func TestFieldTest_Modifiers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		key   string
		value any
		event mapEvent
		want  bool
	}{
		{"plain equality", "Image", "/usr/bin/curl", mapEvent{"Image": {"/usr/bin/curl"}}, true},
		{"plain equality folds case", "Image", "/usr/bin/CURL", mapEvent{"Image": {"/usr/bin/curl"}}, true},
		{"plain equality rejects a substring", "Image", "curl", mapEvent{"Image": {"/usr/bin/curl"}}, false},
		{"plain value honours embedded wildcards", "Image", "*/curl", mapEvent{"Image": {"/usr/bin/curl"}}, true},

		{"contains matches inside", "CommandLine|contains", "dump-keychain", mapEvent{"CommandLine": {"security dump-keychain -d"}}, true},
		{"contains matches at the start", "CommandLine|contains", "security", mapEvent{"CommandLine": {"security dump-keychain"}}, true},
		{"contains rejects an absent substring", "CommandLine|contains", "wget", mapEvent{"CommandLine": {"security dump-keychain"}}, false},

		{"startswith matches a prefix", "Image|startswith", "/usr/bin", mapEvent{"Image": {"/usr/bin/curl"}}, true},
		{"startswith rejects a suffix", "Image|startswith", "curl", mapEvent{"Image": {"/usr/bin/curl"}}, false},

		{"endswith matches a suffix", "Image|endswith", "/curl", mapEvent{"Image": {"/usr/bin/curl"}}, true},
		{"endswith rejects a prefix", "Image|endswith", "/usr", mapEvent{"Image": {"/usr/bin/curl"}}, false},

		{"re matches", "CommandLine|re", `curl\s+-[A-Z]`, mapEvent{"CommandLine": {"curl -O http://x"}}, true},
		{"re rejects", "CommandLine|re", `^wget`, mapEvent{"CommandLine": {"curl -O http://x"}}, false},
		// Faithful to Sigma: |re is NOT case-folded, so an author who wants that writes (?i) themselves. Folding it here would
		// silently widen every imported rule that relies on case.
		{"re is case-sensitive unless the author asks", "CommandLine|re", `^CURL`, mapEvent{"CommandLine": {"curl -O"}}, false},
		{"re honours an inline case-insensitive flag", "CommandLine|re", `(?i)^CURL`, mapEvent{"CommandLine": {"curl -O"}}, true},

		{"a missing field never matches", "Image", "/usr/bin/curl", mapEvent{"CommandLine": {"x"}}, false},
		{"a list-valued field matches on any element", "argv|contains", "-d", mapEvent{"argv": {"security", "dump-keychain", "-d"}}, true},
		{"a list-valued field rejects when no element matches", "argv|contains", "-z", mapEvent{"argv": {"security", "-d"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ft, err := compileFieldTest(tc.key, tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.want, ft.match(tc.event))
		})
	}
}

// TestFieldTest_AllQuantifier pins the one modifier whose meaning is easy to get backwards. |all requires every listed value to
// match, and the values may match in DIFFERENT elements of a list-valued field: `argv|contains|all: [x, y]` asks that x and y
// each appear among the arguments, not that one argument contains both.
func TestFieldTest_AllQuantifier(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		key   string
		value any
		event mapEvent
		want  bool
	}{
		{"default any: one of two matches", "CommandLine|contains", []any{"dump-keychain", "wget"},
			mapEvent{"CommandLine": {"security dump-keychain"}}, true},
		{"all: one of two matches is not enough", "CommandLine|contains|all", []any{"dump-keychain", "wget"},
			mapEvent{"CommandLine": {"security dump-keychain"}}, false},
		{"all: both match", "CommandLine|contains|all", []any{"security", "dump-keychain"},
			mapEvent{"CommandLine": {"security dump-keychain"}}, true},
		{"all across separate list elements", "argv|contains|all", []any{"dump-keychain", "-d"},
			mapEvent{"argv": {"security", "dump-keychain", "-d"}}, true},
		{"all fails when one value is absent from every element", "argv|contains|all", []any{"dump-keychain", "-z"},
			mapEvent{"argv": {"security", "dump-keychain", "-d"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ft, err := compileFieldTest(tc.key, tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.want, ft.match(tc.event))
		})
	}
}

// TestFieldTest_NullMatchesAbsence covers `Field: null` and, critically, its distinction from `Field: ""`. The corpus rule that
// drove this implements BOTH as separate filters, so conflating them would change what that rule suppresses.
func TestFieldTest_NullMatchesAbsence(t *testing.T) {
	t.Parallel()

	null, err := compileFieldTest("CommandLine", nil)
	require.NoError(t, err)
	empty, err := compileFieldTest("CommandLine", "")
	require.NoError(t, err)

	absent := mapEvent{"Image": {"/usr/bin/curl"}}
	present := mapEvent{"CommandLine": {""}}
	filled := mapEvent{"CommandLine": {"curl -O"}}

	assert.True(t, null.match(absent), "null matches a field the event does not carry")
	assert.True(t, null.match(mapEvent{"CommandLine": {}}), "a present but valueless field is absent for matching purposes")
	assert.False(t, null.match(present), "null does not match a present, empty field")
	assert.False(t, null.match(filled))

	assert.True(t, empty.match(present), "the empty string matches a present, empty field")
	assert.False(t, empty.match(absent), "the empty string does not match an absent field")
	assert.False(t, empty.match(filled))
}

// spec:server-detection-rules-engine/an-unsupported-or-meaningless-rule-construct-is-refused-when-the-rule-is-loaded/a-rule-using-an-unimplemented-modifier-is-refused
//
// TestCompileFieldTest_Rejects covers the load-time refusals. Each of these would otherwise produce a rule that evaluates but
// does not mean what it says, which is worse than one that fails to load.
func TestCompileFieldTest_Rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		key   string
		value any
		want  string
	}{
		{"unknown modifier", "CommandLine|base64offset", "x", "uses modifier"},
		{"windash is not implemented", "CommandLine|windash", "x", "uses modifier"},
		{"cidr is not implemented", "DestinationIp|cidr", "10.0.0.0/8", "uses modifier"},
		{"empty field name", "|contains", "x", "empty field name"},
		{"empty value list", "CommandLine|contains", []any{}, "no values"},
		{"regexp combined with a substring modifier", "CommandLine|re|contains", "x", "no defined meaning"},
		{"invalid regexp", "CommandLine|re", "([", "invalid regexp"},
		{"null combined with a modifier", "CommandLine|contains", nil, "no defined meaning"},
		{"unsupported value type", "CommandLine", map[string]any{"a": 1}, "unsupported value type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := compileFieldTest(tc.key, tc.value)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestScalarList_RendersNonStrings pins that a bare number in a rule is compared as its rendered text rather than refused. The
// corpus carries ports and uids unquoted, and YAML hands those over as int.
func TestScalarList_RendersNonStrings(t *testing.T) {
	t.Parallel()

	ft, err := compileFieldTest("DestinationPort", 443)
	require.NoError(t, err)
	assert.True(t, ft.match(mapEvent{"DestinationPort": {"443"}}))
	assert.False(t, ft.match(mapEvent{"DestinationPort": {"80"}}))

	ft, err = compileFieldTest("Elevated", true)
	require.NoError(t, err)
	assert.True(t, ft.match(mapEvent{"Elevated": {"true"}}))
}

// TestCompileFieldTest_RejectsModifierCombinations covers the combinations that have no composed meaning in Sigma. Left alone, the
// last substring modifier silently won, so `Field|contains|startswith` and `Field|startswith|contains` compiled to DIFFERENT
// matchers, neither of them what the author wrote.
func TestCompileFieldTest_RejectsModifierCombinations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		key   string
		value any
		want  string
	}{
		{"contains then startswith", "CommandLine|contains|startswith", "x", "combines substring modifiers"},
		{"startswith then contains", "CommandLine|startswith|contains", "x", "combines substring modifiers"},
		{"endswith then contains", "Image|endswith|contains", "x", "combines substring modifiers"},
		{"a repeated modifier", "CommandLine|contains|contains", "x", "repeats modifier"},
		{"all on a single value quantifies over nothing", "Image|all", "x", "quantifies over nothing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := compileFieldTest(tc.key, tc.value)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestCompileFieldTest_AllowsAllWithOneValueModifier confirms the rejection above is narrow: |all legitimately combines with one
// substring modifier, which is the shape 22 macOS rules use.
func TestCompileFieldTest_AllowsAllWithOneValueModifier(t *testing.T) {
	t.Parallel()

	ft, err := compileFieldTest("CommandLine|contains|all", []any{"a", "b"})
	require.NoError(t, err)
	assert.True(t, ft.match(mapEvent{"CommandLine": {"a and b"}}))
	assert.False(t, ft.match(mapEvent{"CommandLine": {"only a"}}))
}
