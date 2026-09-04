package sigma

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// glob is a wildcard pattern compiled into the literal segments between its stars, built once at load and matched per event.
//
// It implements Sigma's wildcard rules: `*` stands for any run of characters including the empty one, `?` for exactly one
// character, and a backslash escapes the following `*`, `?` or `\\` so it is compared literally. Everything else is literal. 47
// corpus rules escape a wildcard; treating `\*` as a wildcard would silently match far more than the rule says, which is the
// failure mode that produces confident wrong alerts rather than a visible error.
//
// Comparison folds case, because the Sigma specification defines it that way and the corpus relies on it: rules write 'JavaScript'
// and '/PlistBuddy' while the values they match arrive in whatever case the host reported.
//
// Compiling to segments rather than to a regexp keeps two properties the hot path needs. It allocates nothing per match, and it
// never has to escape the pattern: translating Sigma wildcards into regexp syntax means escaping every regexp metacharacter in the
// literal runs, and a missed escape turns a literal '.' or '+' in a file path into a silent over-match.
//
// The backtracking scan it replaces (see matchWildcard, kept as the reference implementation the equivalence property checks
// against) is O(len(value) x len(pattern)): a star followed by a long literal run re-tries that run at every offset of the value.
// An attacker controls the event value, so a value built to keep almost-matching a real corpus pattern drove one field test to 44us
// against a typical 573ns, and a synthetic worst case to 1.5ms. Per event, per rule, per field, that is an ingestion-stall vector
// once the corpus import (#764) multiplies the rule count.
//
// Splitting on stars removes the backtracking. Sigma's `*` matches any run, so the segments between stars must simply appear in
// order: the first anchored at the start, the last at the end, the rest found left to right. Taking the leftmost occurrence of each
// middle segment is optimal, because it leaves the most room for the ones after it, so no choice is ever revisited.
//
// Measured on the same inputs as the reference implementation, 20,000 iterations, all zero-allocation:
//
//	shape                                    reference    compiled
//	typical corpus pattern (`*/MacOS/*`)         460ns      40.1ns
//	corpus pattern, suffix anchor rejects       30.6us      12.3ns
//	corpus pattern, past the anchor             30.6us       7.6us
//	synthetic worst case (`*` + 64 literals)     1.52ms       118ns
//	`?` in a middle segment                      856us       444us
//
// The third row is the honest figure for the attacker-driven case: the second rejects on the suffix before searching anything,
// which is a real and common outcome but compares a full scan against an early exit.
//
// Three things do the work, and each is only sound with a caveat that cost a bug in review. Segments are anchored, so a literal run
// after a star is checked once at the end rather than at every offset. Candidate positions are found by scanning for the possible
// lead bytes of the first rune, which must be computed across its FOLD cycle or a foldable value rune is skipped. And verification
// compares bytes when both sides are ASCII, which must abandon the byte loop on any wide value rune, because a rune folding in from
// outside ASCII occupies more bytes than the segment allots.
//
// This bounds what an attacker-controlled VALUE can do against a fixed pattern. It does not make every pattern linear. A middle
// segment carrying `?` cannot use the byte paths at all, so it walks candidate offsets and stays O(value x segment); that is the
// last row, still faster than the scan it replaces but the shape with the most left in it. Reaching it needs a pattern chosen to be
// pathological, which today means a rule author. Issue #767 is where operator-authored patterns arrive, and is where that residual
// belongs.
type glob struct {
	// segs are the star-separated runs, always at least one: a pattern with n stars has n+1 segments, some possibly empty.
	// segs[0] must match at the start of the value and segs[len-1] at the end, which is what the split leaves implicit.
	segs []globSeg
}

// globSeg is one run of pattern atoms between two stars.
type globSeg struct {
	atoms []globAtom
	// minBytes is the shortest UTF-8 encoding the segment can match, used to abandon a search that cannot fit.
	//
	// It is the minimum across each atom's FOLD CYCLE, not the width of the rune as written. Those differ: `\u017f` is two bytes
	// and folds with the one-byte `s`, so a segment written with it can match a shorter run than its own encoding suggests, and
	// measuring the written width would reject a value that does match.
	minBytes int
	// leadBytes are every possible FIRST byte of a rune that could begin this segment, precomputed across the first atom's fold
	// cycle. Scanning for them is what makes the search skip rather than walk.
	//
	// Soundness rests on two facts. Any match must begin with a rune that folds to the first atom, and every such rune's first byte
	// is in this set, so nothing valid is skipped. And a UTF-8 lead byte is never a continuation byte, so a position found this way
	// is always a rune boundary. Empty when the first atom is `?`, which any rune satisfies.
	leadBytes []byte
	// asciiLiteral is the segment's text when every atom is a literal ASCII rune, which lets verification compare bytes instead of
	// decoding runes. Empty otherwise.
	//
	// It is only a fast path, never the decision: an ASCII segment can still be matched by a value rune that folds to it from
	// outside ASCII (`\u017f` folds to `s`), and such a rune occupies more bytes than the segment allots. The comparison therefore
	// abandons the byte loop the moment it meets a byte outside ASCII and re-runs the span rune by rune.
	asciiLiteral string
}

// globAtom is one pattern element: a literal rune, or `?` standing for exactly one rune.
// cost estimates what matching this pattern against one value can cost, in units of "atoms compared per candidate position".
//
// Only the segments between the first and last contribute. segs[0] anchors to the start of the value and segs[len-1] to the end, so
// each is checked once; a segment with a star on both sides is searched for at every candidate offset, which is the O(value x
// segment) shape #787 left behind and deferred to #767 by name.
//
// The unit is the segment's LENGTH, not its `?` count, and that correction came out of review. The first version counted only `?`
// on the reasoning that a literal segment can use the byte-comparison paths, which is true and does not make it cheap: measured on
// a 4096-byte value, a middle segment of 1024 literal characters costs 1.41ms, the same order as 1024 `?` at 4.10ms. Bounding one
// and not the other left the cheaper-looking half wide open.
func (g glob) cost() int {
	total := 0
	for i := 1; i < len(g.segs)-1; i++ {
		total += len(g.segs[i].atoms)
	}
	return total
}

type globAtom struct {
	r   rune
	any bool
}

// compileGlob splits a pattern into its star-separated segments. Escapes are resolved here, once, so the match path never re-reads
// a backslash.
func compileGlob(pattern string) glob {
	var (
		g   glob
		cur []globAtom
	)
	flush := func() {
		g.segs = append(g.segs, newGlobSeg(cur))
		cur = nil
	}
	for i := 0; i < len(pattern); {
		r, meta, w := patternToken(pattern, i)
		i += w
		switch {
		case meta && r == '*':
			// Adjacent stars collapse. `**` matches exactly what `*` matches, so the second one adds an empty middle segment that
			// the search then walks for every value: measured at 19ns for two stars and 40us for 8192, growing linearly in a
			// pattern an author is free to write. Collapsing costs nothing and removes the growth, which is better than bounding it
			// (review of #767 suggested either; a limit would refuse a pattern that means something harmless).
			if len(cur) == 0 && len(g.segs) > 0 {
				continue
			}
			flush()
		case meta && r == '?':
			cur = append(cur, globAtom{any: true})
		default:
			cur = append(cur, globAtom{r: r})
		}
	}
	flush()
	return g
}

// newGlobSeg precomputes what the search path needs so the hot path does no analysis.
func newGlobSeg(atoms []globAtom) globSeg {
	seg := globSeg{atoms: atoms}
	for _, a := range atoms {
		if a.any {
			// A `?` matches exactly one rune, which is 1 to 4 bytes; the shortest is what bounds the search.
			seg.minBytes++
			continue
		}
		seg.minBytes += minFoldedWidth(a.r)
	}
	if len(atoms) > 0 && !atoms[0].any {
		seg.leadBytes = foldLeadBytes(atoms[0].r)
	}
	if ascii := asciiLiteralOf(atoms); ascii != "" {
		seg.asciiLiteral = ascii
	}
	return seg
}

// asciiLiteralOf returns the segment's text when every atom is a literal ASCII rune, and "" otherwise.
func asciiLiteralOf(atoms []globAtom) string {
	if len(atoms) == 0 {
		return ""
	}
	var b strings.Builder
	for _, a := range atoms {
		if a.any || a.r < 0 || a.r >= utf8.RuneSelf {
			return ""
		}
		// The guard above proves 0 <= r < 0x80, so the conversion cannot truncate.
		b.WriteByte(byte(a.r)) //nolint:gosec // G115: bounded to ASCII on the line above
	}
	return b.String()
}

// foldLeadBytes returns the distinct first bytes of every rune that case-folds together with r, or nil when no filter is sound.
//
// U+FFFD is the nil case. decode maps ANY malformed byte to it with a width of one, so a value can satisfy a U+FFFD atom with a
// single byte anywhere in 0x80-0xFF as well as with the valid three-byte encoding. Filtering on the encoding's lead byte would skip
// every malformed byte, which is a silent false negative on exactly the attacker-controlled values this matcher exists to judge.
func foldLeadBytes(r rune) []byte {
	if r == utf8.RuneError {
		return nil
	}
	var out []byte
	add := func(x rune) {
		var buf [utf8.UTFMax]byte
		utf8.EncodeRune(buf[:], x)
		if !slices.Contains(out, buf[0]) {
			out = append(out, buf[0])
		}
	}
	add(r)
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		add(f)
	}
	return out
}

// minFoldedWidth is the shortest UTF-8 encoding of any rune that case-folds together with r, which is the least a literal atom can
// consume. For ASCII it is 1; it differs only for the handful of runes whose fold cycle crosses an encoding-length boundary.
func minFoldedWidth(r rune) int {
	// A U+FFFD atom can be satisfied by a single malformed byte, because that is what decode returns for one. Measuring it as the
	// three bytes of its valid encoding would reject a value that the reference implementation matches.
	if r == utf8.RuneError {
		return 1
	}
	// RuneLen is never negative here: atoms are decoded with DecodeRuneInString, which yields RuneError rather than a surrogate
	// or an out-of-range rune, and RuneError has a width.
	minWidth := utf8.RuneLen(r)
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if w := utf8.RuneLen(f); w > 0 && w < minWidth {
			minWidth = w
		}
	}
	return minWidth
}

// match reports whether s matches the compiled pattern, folding case.
//
// The shape is the standard one: the first segment is a prefix, the last a suffix, and the middle segments are found in order. A
// pattern with no star has exactly one segment and must therefore consume the whole value.
func (g glob) match(s string) bool {
	lo, ok := g.segs[0].matchAt(s, 0)
	if !ok {
		return false
	}
	if len(g.segs) == 1 {
		// No star anywhere, so the single segment has to account for every byte.
		return lo == len(s)
	}

	hi, ok := g.segs[len(g.segs)-1].matchEndingAt(s, lo)
	if !ok {
		return false
	}
	for _, seg := range g.segs[1 : len(g.segs)-1] {
		end, found := seg.find(s, lo, hi)
		if !found {
			return false
		}
		lo = end
	}
	return true
}

// matchASCIIAt is matchAt's fast path for an all-ASCII-literal segment. decided is false when the comparison has to be redone rune
// by rune, which happens the moment a byte of the value is not ASCII: a value rune outside ASCII can fold INTO an ASCII segment
// (`\u017f` folds to `s`) while occupying more bytes than the segment allots, so a byte-length comparison would read the wrong span.
//
// When decided is true, end is the offset just past the match, or -1 for a definite mismatch. A mismatch between two ASCII bytes is
// definite: both are complete runes, so no rune-level comparison could reach a different answer.
func (s globSeg) matchASCIIAt(v string, i int) (end int, decided bool) {
	lit := s.asciiLiteral
	if lit == "" || i+len(lit) > len(v) {
		return 0, false
	}
	for k := range len(lit) {
		c := v[i+k]
		if c >= utf8.RuneSelf {
			return 0, false
		}
		if !equalFoldASCII(rune(c), rune(lit[k])) {
			return -1, true
		}
	}
	return i + len(lit), true
}

// matchAt reports whether the segment matches starting at byte offset i, returning the offset just past it.
func (s globSeg) matchAt(v string, i int) (int, bool) {
	// Byte-wise comparison when both sides are ASCII, which is nearly every comparison the corpus makes.
	if end, decided := s.matchASCIIAt(v, i); decided {
		return end, end >= 0
	}

	for _, a := range s.atoms {
		if i >= len(v) {
			return 0, false
		}
		r, w := decode(v, i)
		if !a.any && !equalFoldRune(r, a.r) {
			return 0, false
		}
		i += w
	}
	return i, true
}

// matchEndingAt reports whether the segment matches a suffix of v ending exactly at len(v), returning the offset it starts at. The
// start must not fall before lo, which is where the anchored prefix already consumed up to.
func (s globSeg) matchEndingAt(v string, lo int) (int, bool) {
	// Step back one rune per atom. A segment's byte length varies with the runes it matches, so the start cannot be computed by
	// subtraction; it has to be walked.
	start := len(v)
	for range s.atoms {
		if start <= lo {
			// Out of value before out of atoms: the suffix cannot fit alongside the prefix the first segment already took.
			return 0, false
		}
		// The width is never zero, because the guard above leaves start > lo >= 0 and so v[:start] is never empty. And start
		// cannot end up below lo: lo is itself a rune boundary, reached by consuming whole runes, and stepping back one rune at
		// a time visits every boundary in between, so the guard above catches equality first.
		_, w := utf8.DecodeLastRuneInString(v[:start])
		start -= w
	}
	end, ok := s.matchAt(v, start)
	if !ok || end != len(v) {
		return 0, false
	}
	return start, true
}

// find returns the offset just past the leftmost occurrence of the segment starting at or after lo and ending at or before hi.
//
// Leftmost is the right choice and needs no backtracking: a later occurrence can only leave less room for the segments that follow,
// so if the leftmost one fails to lead to a match, no other could.
func (s globSeg) find(v string, lo, hi int) (int, bool) {
	if s.minBytes > hi-lo {
		return 0, false
	}
	for i := lo; i+s.minBytes <= hi; {
		// Skip to the next position that could possibly begin a match, rather than testing every rune. On a value packed with
		// near-misses this is the difference between verifying at every offset and verifying only where the first rune fits.
		if len(s.leadBytes) > 0 {
			j := indexAnyByte(v[i:hi], s.leadBytes)
			if j < 0 {
				return 0, false
			}
			i += j
			if i+s.minBytes > hi {
				return 0, false
			}
		}
		if end, ok := s.matchAt(v, i); ok && end <= hi {
			return end, true
		}
		_, w := decode(v, i)
		i += w
	}
	return 0, false
}

// indexAnyByte returns the offset of the first byte in s that appears in set, or -1. The set holds at most a few bytes, so calling
// the SIMD-backed strings.IndexByte once each and taking the earliest hit beats scanning the string by hand.
func indexAnyByte(s string, set []byte) int {
	best := -1
	for _, b := range set {
		if at := strings.IndexByte(s, b); at >= 0 && (best < 0 || at < best) {
			best = at
		}
	}
	return best
}
