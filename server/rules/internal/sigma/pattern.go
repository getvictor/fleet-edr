// Package sigma evaluates the single-event subset of the Sigma detection format (issue #760).
//
// The subset is not a guess. It is what the upstream corpus actually uses, measured across SigmaHQ's 3,141 endpoint rules and the
// 69 under rules/macos/ that this engine will import first:
//
//   - Modifiers: contains (60 macOS rules), endswith (58), all (22), re (2), startswith (1). Nothing else appears in a macOS rule.
//     base64offset and cidr, which issue #760 originally listed, are used by ZERO macOS rules (7 and 21 corpus-wide), so they are
//     deliberately absent rather than overlooked. windash (80 corpus-wide, Windows only) is the one to expect first when the
//     catalog goes cross-platform.
//   - Wildcards in plain values: 31 of the 69 macOS rules. These carry no modifier, so a census of modifiers alone misses them.
//   - Aggregation and correlation: zero rules, corpus-wide. Not merely rare on macOS: absent everywhere, which is why this
//     evaluator has no aggregation surface at all.
//
// Everything here is compiled once at load and evaluated many times: a rule is matched per event, per rule, so the hot path
// allocates nothing and the cost of preparing a matcher is paid at start-up.
package sigma

import (
	"unicode"
	"unicode/utf8"
)

// patternToken decodes one pattern element at offset i. It returns the rune to compare, whether that rune is an active wildcard
// metacharacter, and how many bytes the element occupies. A backslash before `*`, `?` or `\\` escapes it into a literal; a
// backslash before anything else is itself a literal, which is what keeps Windows paths such as `C:\Windows` working.
func patternToken(p string, i int) (r rune, meta bool, w int) {
	r, w = decode(p, i)
	if r == '\\' && i+w < len(p) {
		if nr, nw := decode(p, i+w); nr == '*' || nr == '?' || nr == '\\' {
			return nr, false, w + nw
		}
	}
	if r == '*' || r == '?' {
		return r, true, w
	}
	return r, false, w
}

// decode returns the rune at offset i and its width, or (utf8.RuneError, 1) past the end. Callers guard the end themselves; the
// safe return keeps a malformed tail from panicking.
func decode(s string, i int) (rune, int) {
	if i >= len(s) {
		return utf8.RuneError, 1
	}
	return utf8.DecodeRuneInString(s[i:])
}

func equalFoldRune(a, b rune) bool {
	if a == b {
		return true
	}
	// ASCII against ASCII is the overwhelming majority of comparisons and needs none of the machinery below: two ASCII letters fold
	// together exactly when they differ only in bit 5. Worth special-casing because SimpleFold does a table lookup per call, and
	// this runs once per rune of every segment comparison.
	//
	// Only when BOTH sides are ASCII: `\u017f` folds with `s` and is not ASCII, so a mixed pair has to fall through.
	if a < utf8.RuneSelf && b < utf8.RuneSelf {
		const asciiCaseBit = 'a' - 'A'
		lowerA, lowerB := a|asciiCaseBit, b|asciiCaseBit
		return lowerA == lowerB && lowerA >= 'a' && lowerA <= 'z'
	}
	// SimpleFold walks the cycle of runes that fold together, returning to the start; a cycle is at most a few entries long.
	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
	}
	return false
}

// hasWildcard reports whether a value needs the wildcard path at all: it carries an active `*` or `?`, or an escape sequence that
// has to be unwrapped. A value with neither is compared with a plain case-insensitive equality, which is both faster and exactly
// what Sigma specifies.
//
// Escapes must answer true even though they match literally. `C:\\\\Windows` denotes one backslash, so sending it down the literal
// path would compare the two written characters against the one real one and never match.
func hasWildcard(v string) bool {
	for i := 0; i < len(v); {
		r, w := decode(v, i)
		if r == '*' || r == '?' {
			return true
		}
		if r == '\\' && i+w < len(v) {
			if nr, _ := decode(v, i+w); nr == '*' || nr == '?' || nr == '\\' {
				return true
			}
		}
		i += w
	}
	return false
}

// matchGlobExact is matchWildcard's case-SENSITIVE twin, used for search identifiers rather than event values. Sigma folds case when
// comparing values and does not when resolving identifiers, so the two callers genuinely need different comparisons.
func matchGlobExact(s, pattern string) bool {
	var (
		si, pi int
		starPi = -1
		starSi int
	)
	for si < len(s) {
		pr, meta, pw := patternToken(pattern, pi)
		sr, sw := decode(s, si)
		switch {
		case pi < len(pattern) && meta && pr == '*':
			starPi, pi = pi, pi+pw
			starSi = si
		case pi < len(pattern) && ((meta && pr == '?') || (!meta && sr == pr)):
			si += sw
			pi += pw
		case starPi >= 0:
			_, w := decode(s, starSi)
			starSi += w
			si = starSi
			_, _, pw := patternToken(pattern, starPi)
			pi = starPi + pw
		default:
			return false
		}
	}
	for pi < len(pattern) {
		r, meta, w := patternToken(pattern, pi)
		if !meta || r != '*' {
			return false
		}
		pi += w
	}
	return true
}
