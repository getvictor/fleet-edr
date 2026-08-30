package sigma

import (
	"strings"
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
//	typical corpus pattern (`*/MacOS/*`)         546ns      22.5ns
//	corpus pattern, suffix anchor rejects       43.9us      18.7ns
//	corpus pattern, past the anchor             43.9us       6.5us
//	synthetic worst case (`*` + 64 literals)     1.52ms       236ns
//	`?` in a middle segment                      829us       326us
//
// The third row is the honest one for the attacker-driven case: the second rejects on the suffix before searching anything, which
// is a real and common outcome but compares a full scan against an early exit.
//
// This bounds what an attacker-controlled VALUE can do against a fixed pattern. It does not make every pattern linear. A middle
// segment carrying `?` cannot use a substring search, so it walks candidate offsets and stays O(value x segment); that is the last
// row, still 2.5x faster than the scan it replaces but the shape with the most left in it. Reaching it needs a pattern chosen to be
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
	minBytes int
	// literal is the segment's text when every atom is a literal, so the search can use strings.Index rather than walking atoms.
	// Empty when the segment holds a `?`, which no substring search can express.
	literal string
	// asciiOnly reports whether literal is pure ASCII, which is what makes a byte-wise case-insensitive search sound: folding a
	// non-ASCII rune can change its encoded length, so the byte offsets a byte search returns would not be rune boundaries.
	asciiOnly bool
}

// globAtom is one pattern element: a literal rune, or `?` standing for exactly one rune.
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
	seg := globSeg{atoms: atoms, asciiOnly: true}
	var b strings.Builder
	literal := true
	for _, a := range atoms {
		if a.any {
			// A `?` matches exactly one rune, which is 1 to 4 bytes; the shortest is what bounds the search.
			seg.minBytes++
			literal = false
			continue
		}
		seg.minBytes += utf8.RuneLen(a.r)
		if a.r >= utf8.RuneSelf {
			seg.asciiOnly = false
		}
		b.WriteRune(a.r)
	}
	if literal {
		seg.literal = b.String()
	} else {
		seg.asciiOnly = false
	}
	return seg
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

// matchAt reports whether the segment matches starting at byte offset i, returning the offset just past it.
func (s globSeg) matchAt(v string, i int) (int, bool) {
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
		_, w := utf8.DecodeLastRuneInString(v[:start])
		if w == 0 {
			return 0, false
		}
		start -= w
	}
	if start < lo {
		return 0, false
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
	// An all-literal ASCII segment is a plain substring search, which strings.Index does far faster than walking atoms. Case is
	// folded by searching for both cases of the first byte and verifying the rest, so nothing is lowered or allocated.
	if s.literal != "" && s.asciiOnly {
		return s.findLiteral(v, lo, hi)
	}
	for i := lo; i+s.minBytes <= hi; {
		if end, ok := s.matchAt(v, i); ok && end <= hi {
			return end, true
		}
		_, w := decode(v, i)
		i += w
	}
	return 0, false
}

// findLiteral is find for a segment that is pure ASCII with no `?`.
//
// Two passes, both skipping rather than walking. The first is an exact-case strings.Index, which is SIMD-accelerated and is what a
// well-formed value usually satisfies. The second folds case, and rather than testing every offset it jumps between positions whose
// first byte could begin the literal in either case. That distinction is the difference between scanning 4,000 offsets and scanning
// the few hundred that could possibly match: measured on a 4 KB value packed with near-misses, 21.6us against 1.5us.
func (s globSeg) findLiteral(v string, lo, hi int) (int, bool) {
	if at := strings.Index(v[lo:hi], s.literal); at >= 0 {
		return lo + at + len(s.literal), true
	}

	lower, upper := foldASCII(s.literal[0])
	for i := lo; i+len(s.literal) <= hi; i++ {
		if c := v[i]; c != lower && c != upper {
			continue
		}
		if strings.EqualFold(v[i:i+len(s.literal)], s.literal) {
			return i + len(s.literal), true
		}
	}
	return 0, false
}

// foldASCII returns the two ASCII cases of b. Both are b when it is not a letter, which lets the caller take a single-scan path.
func foldASCII(b byte) (lower, upper byte) {
	switch {
	case b >= 'a' && b <= 'z':
		return b, b - ('a' - 'A')
	case b >= 'A' && b <= 'Z':
		return b + ('a' - 'A'), b
	default:
		return b, b
	}
}
