package sigma

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// globAlphabet is deliberately tiny and adversarial: a couple of letters in both cases so folding is exercised, the two wildcard
// metacharacters, a backslash so escapes are generated, a slash because corpus patterns are paths, and one multi-byte rune so the
// rune-stepping in matchEndingAt is not tested only against ASCII.
var globAlphabet = []string{"a", "A", "b", "B", "/", "*", "?", "\\", "é"}

func drawGlobString(t *rapid.T, label string, maxLen int) string {
	n := rapid.IntRange(0, maxLen).Draw(t, label+"_len")
	var b strings.Builder
	for range n {
		b.WriteString(rapid.SampledFrom(globAlphabet).Draw(t, label+"_ch"))
	}
	return b.String()
}

// drawValueFor builds a value from the pattern, so the property spends its budget on inputs where the two implementations could
// actually disagree.
//
// Independently random pattern/value pairs are worthless here: two random 12-character strings essentially never match, so the
// property compares false against false and passes whatever the implementation does. Measured, that is exactly what happened, and
// it let a mutant that removed case folding entirely survive.
//
// So each `*` is filled with a random run and each `?` with one random rune, producing a value that matches by construction; then
// the result is perturbed about half the time. The perturbations are the interesting part: flipping case probes folding, appending
// probes the suffix anchor, and dropping a rune probes the anchors and the `?` width.
func drawValueFor(t *rapid.T, pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); {
		r, meta, w := patternToken(pattern, i)
		i += w
		switch {
		case meta && r == '*':
			for range rapid.IntRange(0, 3).Draw(t, "fill") {
				b.WriteString(rapid.SampledFrom(globFillAlphabet).Draw(t, "fill_ch"))
			}
		case meta && r == '?':
			b.WriteString(rapid.SampledFrom(globFillAlphabet).Draw(t, "any_ch"))
		default:
			b.WriteRune(r)
		}
	}
	v := b.String()

	switch rapid.IntRange(0, 4).Draw(t, "perturb") {
	case 0:
		return v
	case 1:
		return strings.ToUpper(v)
	case 2:
		return strings.ToLower(v)
	case 3:
		return v + rapid.SampledFrom(globFillAlphabet).Draw(t, "suffix_ch")
	default:
		if runes := []rune(v); len(runes) > 0 {
			drop := rapid.IntRange(0, len(runes)-1).Draw(t, "drop")
			return string(append(append([]rune{}, runes[:drop]...), runes[drop+1:]...))
		}
		return v
	}
}

// globFillAlphabet is what a `*` or `?` is filled with. It excludes the metacharacters so a fill never changes the pattern's
// meaning when the value is read back, and includes a multi-byte rune so rune-width handling is exercised.
var globFillAlphabet = []string{"a", "A", "b", "/", "é"}

// spec:server-detection-rules-engine/wildcard-matching-cost-does-not-depend-on-the-event-value-being-adversarial/compilation-does-not-change-what-a-pattern-matches
//
// TestGlobMatchesTheBacktrackingScan is the equivalence gate for the compiled matcher (issue #787).
//
// matchWildcard is the reference implementation: the backtracking scan that shipped in #786, whose semantics the corpus rules were
// read against. The compiled form is an optimisation, so any disagreement is a bug in the compiled form, and a detection engine
// that answers a match differently after an optimisation is the worst kind of regression: it changes what fires, silently.
//
// Values are built from the pattern rather than drawn independently; see drawValueFor for why that is the whole difference between
// a property that bites and one that does not.
func TestGlobMatchesTheBacktrackingScan(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		pattern := drawGlobString(t, "pattern", 12)
		value := drawValueFor(t, pattern)

		require.Equal(t, matchWildcard(value, pattern), compileGlob(pattern).match(value),
			"pattern=%q value=%q", pattern, value)
	})
}

// TestGlobMatchesTheBacktrackingScanOnUnrelatedValues keeps a share of the budget on independently drawn values, which is where a
// spurious MATCH would show up rather than a spurious miss.
func TestGlobMatchesTheBacktrackingScanOnUnrelatedValues(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		pattern := drawGlobString(t, "pattern", 8)
		value := drawGlobString(t, "value", 40)

		require.Equal(t, matchWildcard(value, pattern), compileGlob(pattern).match(value),
			"pattern=%q value=%q", pattern, value)
	})
}

// TestGlobKnownShapes pins the cases the property would only reach by luck, and the ones a reader wants to see stated.
func TestGlobKnownShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{"no star must consume the whole value", "abc", "abc", true},
		{"no star rejects a prefix match", "abc", "abcd", false},
		{"bare star matches anything", "*", "anything", true},
		{"bare star matches empty", "*", "", true},
		{"empty pattern matches only empty", "", "", true},
		{"empty pattern rejects non-empty", "", "x", false},
		{"prefix anchor", "abc*", "abcdef", true},
		{"suffix anchor", "*def", "abcdef", true},
		{"both anchors with a gap", "a*f", "abcdef", true},
		{"gap cannot borrow from the prefix", "a*c", "a", false},
		{"middle segment in order", "*bc*", "abcd", true},
		{"middle segments out of order do not match", "*cd*ab*", "abcd", false},
		{"case is folded", "*ABC*", "xxabcxx", true},
		{"question mark is exactly one rune", "a?c", "abc", true},
		{"question mark does not match empty", "a?c", "ac", false},
		{"question mark spans a multi-byte rune", "a?c", "aéc", true},
		{"escaped star is literal", `a\*c`, "a*c", true},
		{"escaped star does not wildcard", `a\*c`, "abc", false},
		{"escaped question mark is literal", `a\?c`, "a?c", true},
		{"trailing backslash is literal", `a\`, `a\`, true},
		{"multi-byte suffix anchor", "*é", "abé", true},
		{"multi-byte suffix rejects a shorter value", "*é", "é", true},
		{"adjacent stars collapse", "a**c", "abc", true},
		// A middle segment must not eat runes the suffix anchor still needs. matchAt stops at the end of the value, not at the
		// suffix boundary, so without the bound in find these three question marks would swallow all three runes and the trailing
		// literal would match nothing at all. The property generator never produced this shape; it is here deliberately.
		{"question marks cannot borrow from the suffix", "*???*é", "ééé", false},
		{"question marks fit when the value is long enough", "*???*é", "éééé", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, compileGlob(tc.pattern).match(tc.value), "compiled")
			assert.Equal(t, tc.want, matchWildcard(tc.value, tc.pattern), "reference implementation must agree")
		})
	}
}

// matchWildcard is the REFERENCE implementation: the backtracking scan that shipped in #786, kept here, frozen, as the oracle the
// compiled matcher is checked against. It lives in the test file rather than in the package because nothing in production calls it
// any more, and because an oracle that is edited alongside the implementation it checks stops being an oracle.
//
// The scan is O(len(s) x len(pattern)): a star followed by a long literal run re-tries that run at every offset of the value. That
// cost is why glob.go exists.
func matchWildcard(s, pattern string) bool {
	// star tracks the most recent `*` in the pattern and the position in s where it started consuming, so a failed match can
	// backtrack and let that star swallow one more character. This is the standard linear-space glob scan.
	var (
		si, pi int
		starPi = -1
		starSi int
	)
	for si < len(s) {
		pr, meta, pw := patternToken(pattern, pi)
		switch {
		case pi < len(pattern) && meta && pr == '*':
			starPi, pi = pi, pi+pw
			starSi = si
		case pi < len(pattern) && ((meta && pr == '?') || (!meta && equalFoldAt(s, si, pr))):
			_, sw := decode(s, si)
			si += sw
			pi += pw
		case starPi >= 0:
			// No match here, but a star is open: give it one more character of s and retry the rest of the pattern.
			_, sw := decode(s, starSi)
			starSi += sw
			si = starSi
			_, _, w := patternToken(pattern, starPi)
			pi = starPi + w
		default:
			return false
		}
	}
	// s is exhausted; the pattern matches only if what remains is stars.
	for pi < len(pattern) {
		r, meta, w := patternToken(pattern, pi)
		if !meta || r != '*' {
			return false
		}
		pi += w
	}
	return true
}

// equalFoldAt reports whether the rune at s[si] is case-fold equivalent to pr, without allocating a lowered copy of either string.
//
// It walks Unicode's simple-fold cycle rather than comparing unicode.ToLower of each side, because those differ: ToLower maps the
// Greek final sigma and the long s to themselves, so `ToLower('S') == ToLower('\u017f')` is false while strings.EqualFold treats them
// as equal. The plain-value path uses strings.EqualFold, so lowering here would make a rule's meaning depend on whether it happened
// to contain a wildcard.
func equalFoldAt(s string, si int, pr rune) bool {
	sr, _ := decode(s, si)
	return equalFoldRune(sr, pr)
}

// The three benchmarks below mirror BenchmarkMatchWildcard* in pattern_test.go exactly, on the same inputs, so the pair reads as a
// before-and-after. Those measure the reference implementation; these measure what ships. The pattern is compiled outside the loop
// because that is where it is compiled in production: once, at rule load.

// BenchmarkGlobAdversarial is the shape that makes a backtracking glob quadratic: a star followed by a long literal run that almost
// matches. Splitting on stars makes the run a suffix anchor, so it is checked once at the end of the value instead of at every
// offset.
func BenchmarkGlobAdversarial(b *testing.B) {
	value := strings.Repeat("a", 4096)
	g := compileGlob("*" + strings.Repeat("a", 64) + "b")
	b.ReportAllocs()
	for b.Loop() {
		if g.match(value) {
			b.Fatal("must not match")
		}
	}
}

// BenchmarkGlobCorpusWorstCase is the one that decides whether this change was worth making: an attacker controls the event VALUE
// but not the pattern, so the exposure is what a pattern the corpus already ships can be driven to.
func BenchmarkGlobCorpusWorstCase(b *testing.B) {
	value := strings.Repeat("/Resources/x", 340) // ~4 KB, the shape of a long argv
	g := compileGlob("*Framework.framework/*/Resources/*.sh")
	b.ReportAllocs()
	for b.Loop() {
		if g.match(value) {
			b.Fatal("must not match")
		}
	}
}

// BenchmarkGlobTypical is the shape the corpus actually contains. It is the number that must not regress: it runs per event, per
// rule, per field, where the two above need a value built to provoke them.
func BenchmarkGlobTypical(b *testing.B) {
	value := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	g := compileGlob("*/MacOS/*")
	b.ReportAllocs()
	for b.Loop() {
		if !g.match(value) {
			b.Fatal("must match")
		}
	}
}

// BenchmarkGlobCorpusWorstCasePastTheAnchor is the honest worst case for the compiled matcher.
//
// BenchmarkGlobCorpusWorstCase above rejects in tens of nanoseconds because the value does not end in `.sh`, so the suffix anchor
// answers before any searching happens. That is a real and common outcome, but quoting it as the speedup would overstate the case:
// it compares a full scan against an early exit. This value ends in `.sh` and is packed with near-misses of the first segment, so
// the anchors pass and every middle segment is actually searched.
func BenchmarkGlobCorpusWorstCasePastTheAnchor(b *testing.B) {
	// "Framework.framewor" repeated: one character short of the segment, so every candidate position fails late.
	value := strings.Repeat("Framework.framewor/", 215) + ".sh" // ~4 KB
	g := compileGlob("*Framework.framework/*/Resources/*.sh")
	b.ReportAllocs()
	for b.Loop() {
		if g.match(value) {
			b.Fatal("must not match")
		}
	}
}

// BenchmarkGlobQuestionMarkSegment measures the residual: a middle segment carrying `?` cannot use a substring search, so it walks
// candidate offsets. This is the shape issue #787 leaves open, and it needs a pattern chosen to be pathological rather than a value.
func BenchmarkGlobQuestionMarkSegment(b *testing.B) {
	value := strings.Repeat("a", 4096) + "b"
	g := compileGlob("*" + strings.Repeat("a", 32) + "?c*b")
	b.ReportAllocs()
	for b.Loop() {
		if g.match(value) {
			b.Fatal("must not match")
		}
	}
}

// BenchmarkMatchWildcardQuestionMarkSegment is the reference implementation on BenchmarkGlobQuestionMarkSegment's input, so the
// residual can be compared like for like rather than against a different shape. Without this pair it would be impossible to tell
// whether the compiled matcher improved that case, left it alone, or made it worse.
func BenchmarkMatchWildcardQuestionMarkSegment(b *testing.B) {
	value := strings.Repeat("a", 4096) + "b"
	pattern := "*" + strings.Repeat("a", 32) + "?c*b"
	b.ReportAllocs()
	for b.Loop() {
		if matchWildcard(value, pattern) {
			b.Fatal("must not match")
		}
	}
}

// spec:server-detection-rules-engine/wildcard-matching-cost-does-not-depend-on-the-event-value-being-adversarial/a-literal-run-after-a-star-is-checked-once-not-at-every-offset
//
// TestCompileGlobDecomposesIntoAnchoredSegments pins the structure that bounds the cost, rather than asserting a timing.
//
// The benchmarks record what the change is worth; a unit test that asserted a duration would be measuring the machine, and this
// repository already has one flaky time-boundary test too many. What actually removes the backtracking is the decomposition: a
// literal run after a star becomes the LAST segment, which is tested once against the end of the value. If that shape is wrong the
// cost claim is wrong, whatever a stopwatch says.
func TestCompileGlobDecomposesIntoAnchoredSegments(t *testing.T) {
	t.Parallel()

	literals := func(g glob) []string {
		out := make([]string, 0, len(g.segs))
		for _, seg := range g.segs {
			out = append(out, seg.literal)
		}
		return out
	}

	cases := []struct {
		name    string
		pattern string
		want    []string
	}{
		// The adversarial shape: the long run lands in the final segment, so it is a suffix check rather than a scan.
		{"star then literal run anchors the run at the end", "*aaaa", []string{"", "aaaa"}},
		{"no star is one segment", "abc", []string{"abc"}},
		{"bare star is two empty segments", "*", []string{"", ""}},
		{"leading and trailing stars leave empty anchors", "*mid*", []string{"", "mid", ""}},
		{"a real corpus pattern", "*Framework.framework/*/Resources/*.sh",
			[]string{"", "Framework.framework/", "/Resources/", ".sh"}},
		{"escaped star does not split", `a\*b`, []string{"a*b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, literals(compileGlob(tc.pattern)))
		})
	}

	// A `?` leaves the segment without a literal form, because no substring search can express it.
	seg := compileGlob("*a?c*").segs[1]
	assert.Empty(t, seg.literal, "a segment carrying ? has no literal form")
	assert.Equal(t, 3, seg.minBytes, "and its minimum width is one byte per atom")
}
