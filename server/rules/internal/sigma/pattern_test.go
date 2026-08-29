package sigma

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMatchWildcard covers the primitive every non-regexp value comparison runs through. The negative cases carry the weight: a
// wildcard matcher that is merely too permissive still passes every positive test while silently widening every rule built on it.
func TestMatchWildcard(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		s    string
		p    string
		want bool
	}{
		{"exact", "/usr/bin/curl", "/usr/bin/curl", true},
		{"exact is case-insensitive per the Sigma spec", "/usr/bin/CURL", "/usr/bin/curl", true},
		{"leading star", "/usr/bin/curl", "*curl", true},
		{"trailing star", "/usr/bin/curl", "/usr/*", true},
		{"star in the middle", "/usr/bin/curl", "/usr/*/curl", true},
		{"star matches the empty run", "/usr/curl", "/usr/*curl", true},
		{"bare star matches everything", "anything", "*", true},
		{"bare star matches empty", "", "*", true},
		{"question mark matches exactly one", "abc", "a?c", true},
		{"question mark does not match zero", "ac", "a?c", false},
		{"question mark does not match two", "abbc", "a?c", false},
		{"literal mismatch", "/usr/bin/curl", "/usr/bin/wget", false},
		{"prefix is not a match without a star", "/usr/bin/curl", "/usr/bin", false},
		{"suffix is not a match without a star", "/usr/bin/curl", "curl", false},
		{"empty pattern matches only empty", "", "", true},
		{"empty pattern rejects non-empty", "a", "", false},
		{"trailing stars after exhaustion", "abc", "abc***", true},
		{"backtracking: star must give ground", "aaa", "*a", true},
		{"backtracking across a longer tail", "aaabbb", "*abbb", true},
		{"regexp metacharacters stay literal", "a.c", "a.c", true},
		{"a dot does not behave as regexp any-char", "abc", "a.c", false},
		{"a plus stays literal", "c++", "c++", true},
		// The real shape from the Chrome rules, which is why nested stars have to backtrack correctly.
		{
			"corpus: framework version wildcard",
			"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/1.2.3/Resources/install.sh",
			"*Framework.framework/*/Resources/*.sh", true,
		},
		{
			"corpus: wrong extension",
			"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/1.2.3/Resources/install.py",
			"*Framework.framework/*/Resources/*.sh", false,
		},
		{"unicode is folded too", "CAFÉ", "café", true},
		{"unicode under a star", "/tmp/café/x", "*café*", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, matchWildcard(tc.s, tc.p))
		})
	}
}

func TestHasWildcard(t *testing.T) {
	t.Parallel()

	assert.True(t, hasWildcard("a*b"))
	assert.True(t, hasWildcard("a?b"))
	assert.False(t, hasWildcard("ab"))
	assert.False(t, hasWildcard(""))
	// Escapes must take the wildcard path even though they compare literally: the escape is unwrapped there, so routing
	// `a\\b` (one real backslash) down the literal path would compare two written characters against one.
	assert.True(t, hasWildcard(`a\*b`), "an escaped star still needs unwrapping")
	assert.True(t, hasWildcard(`a\?b`))
	assert.True(t, hasWildcard(`a\\b`), "an escaped backslash needs unwrapping")
	assert.False(t, hasWildcard(`C:\Windows`), "a backslash before an ordinary character is just a literal")
	assert.False(t, hasWildcard(`trailing\`), "a dangling backslash escapes nothing")
}

// spec:server-detection-rules-engine/rules-written-in-the-sigma-format-are-evaluated-against-a-single-event/an-escaped-wildcard-is-matched-literally
//
// TestMatchWildcard_Escapes covers Sigma's backslash escaping. 47 corpus rules escape a wildcard, and an escape treated as a live
// wildcard matches far more than the rule says, which shows up as extra alerts rather than as an error.
func TestMatchWildcard_Escapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		s    string
		p    string
		want bool
	}{
		{"escaped star is literal", "a*b", `a\*b`, true},
		{"escaped star does not act as a wildcard", "axb", `a\*b`, false},
		{"escaped star does not swallow a run", "axxxb", `a\*b`, false},
		{"escaped question is literal", "a?b", `a\?b`, true},
		{"escaped question does not match another character", "axb", `a\?b`, false},
		{"escaped backslash is one literal backslash", `a\b`, `a\\b`, true},
		{"a backslash before an ordinary character stays literal", `C:\Windows`, `C:\Windows`, true},
		// Sigma's own trap: in `*\System32\*` the trailing `\*` is an ESCAPED asterisk, so the pattern demands a literal `*` at
		// the end and does not match an ordinary path. Writing `\\*` (escaped backslash, then a live wildcard) is what an author
		// means here. Both directions are pinned so the escape cannot silently drift back into being a wildcard.
		{"trailing escaped star demands a literal star", `C:\Windows\System32\cmd.exe`, `*\System32\*`, false},
		{"escaped backslash then a live star matches the path", `C:\Windows\System32\cmd.exe`, `*\System32\\*`, true},
		{"and it really does end at a literal star", `C:\System32*`, `*\System32\*`, true},
		{"an escape can follow a star", "prefix*suffix", `*\*suffix`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, matchWildcard(tc.s, tc.p))
		})
	}
}

// TestMatchWildcard_UsesSimpleFold pins that the wildcard path folds case the same way strings.EqualFold does on the plain path.
// unicode.ToLower is NOT equivalent: it maps the long s and the final sigma to themselves, so a rule would mean something different
// depending only on whether it happened to contain a wildcard.
func TestMatchWildcard_UsesSimpleFold(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		s    string
		p    string
	}{
		{"long s folds with capital S", "S", "\u017f"},
		{"long s folds under a wildcard", "MEASURE", "*\u017fURE"},
		{"final sigma folds with capital sigma", "\u03a3", "\u03c2"},
		{"final sigma folds with lowercase sigma", "\u03c3", "\u03c2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.True(t, matchWildcard(tc.s, tc.p), "wildcard path must fold")
			// The plain path is the reference: whatever strings.EqualFold says for the unstarred pair, the wildcard path must agree.
			if !hasWildcard(tc.p) {
				assert.True(t, strings.EqualFold(tc.s, tc.p), "reference: the plain path folds these too")
			}
		})
	}
}

// TestMatchGlobExact_IsCaseSensitive pins the deliberate asymmetry: event VALUES fold case, search IDENTIFIERS do not.
func TestMatchGlobExact_IsCaseSensitive(t *testing.T) {
	t.Parallel()

	assert.True(t, matchGlobExact("sel_1", "sel_*"))
	assert.False(t, matchGlobExact("sel_1", "SEL_*"), "an identifier glob must not fold case")
	assert.True(t, matchWildcard("sel_1", "SEL_*"), "whereas the value matcher does, by specification")
	assert.True(t, matchGlobExact("selection", "selection"))
	assert.False(t, matchGlobExact("selection", "filter*"))
	// Backtracking and trailing-star paths, which decide which searches a quantifier sweeps in.
	assert.True(t, matchGlobExact("sel_aaa", "*aaa"), "the star must give ground and retry")
	assert.True(t, matchGlobExact("selection_1", "sel*ion_?"))
	assert.False(t, matchGlobExact("selection_12", "sel*ion_?"), "? matches exactly one")
	assert.True(t, matchGlobExact("sel", "sel***"), "trailing stars after the value is exhausted")
	assert.False(t, matchGlobExact("sel", "sel*x"), "a literal after the star must still match")
	assert.True(t, matchGlobExact("", "*"))
	assert.False(t, matchGlobExact("a", ""))
}

// BenchmarkMatchWildcardAdversarial measures the shape that makes a backtracking glob quadratic: a star followed by a long literal
// run that almost matches. Real Sigma patterns are a star and a short suffix, so this is the pathological end, recorded as a number
// rather than left as an assumption.
func BenchmarkMatchWildcardAdversarial(b *testing.B) {
	value := strings.Repeat("a", 4096)
	pattern := "*" + strings.Repeat("a", 64) + "b"
	b.ReportAllocs()
	for b.Loop() {
		if matchWildcard(value, pattern) {
			b.Fatal("must not match")
		}
	}
}

// BenchmarkMatchWildcardCorpusWorstCase is the question that decides whether the adversarial number above matters today: an
// attacker controls the event VALUE (a command line) but not the pattern, so the risk is real only if a pattern the corpus already
// ships can be driven into the quadratic case. This uses a real macOS rule pattern against a value built to keep almost matching it.
func BenchmarkMatchWildcardCorpusWorstCase(b *testing.B) {
	value := strings.Repeat("/Resources/x", 340) // ~4 KB, the shape of a long argv
	b.ReportAllocs()
	for b.Loop() {
		if matchWildcard(value, "*Framework.framework/*/Resources/*.sh") {
			b.Fatal("must not match")
		}
	}
}

// BenchmarkMatchWildcardTypical is the shape the corpus actually contains, for contrast with the adversarial case.
func BenchmarkMatchWildcardTypical(b *testing.B) {
	value := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	b.ReportAllocs()
	for b.Loop() {
		if !matchWildcard(value, "*/MacOS/*") {
			b.Fatal("must match")
		}
	}
}
