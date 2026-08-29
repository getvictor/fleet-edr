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

// matchWildcard reports whether s matches pattern under Sigma's wildcard rules: `*` stands for any run of characters including the
// empty one, `?` for exactly one character, and a backslash escapes the following `*`, `?` or `\\` so it is compared literally.
// Everything else is literal. 47 corpus rules escape a wildcard; treating `\*` as a wildcard would silently match far more than the
// rule says, which is the failure mode that produces confident wrong alerts rather than a visible error.
//
// Comparison is case-insensitive because the Sigma specification defines it that way, and the corpus relies on it: rules write
// 'JavaScript' and '/PlistBuddy' while the values they match arrive in whatever case the host reported.
//
// The implementation walks both strings with a backtracking scan rather than compiling to a regexp. Two reasons, in order of
// weight. First, it allocates nothing, which is the property the hot path needs. Second, Sigma wildcards are not regexp syntax:
// translating them means escaping every regexp metacharacter in the literal runs, and a missed escape turns a literal '.' or '+'
// in a file path into a silent over-match. A path-matching rule that quietly matches more than it says is the failure mode least
// likely to be noticed, because it produces alerts rather than silence.
//
// The scan is O(len(s) x len(pattern)) in the worst case, which needs a pattern whose star is followed by a long literal run that
// keeps almost-matching against a value made of that same run. Measured rather than assumed, on an M-series laptop with a 4 KB
// value: a typical corpus pattern costs 0.8 us, a real corpus pattern against a value built to keep almost-matching it costs 89 us,
// and a synthetic worst case (`*` then 64 literal characters) costs 3.6 ms. All three allocate nothing.
//
// An attacker controls the event value but not the pattern, so today's exposure is the middle number, and it needs deliberately
// long near-matching values. That is tolerable for the 11 rules we ship and worth bounding before the corpus import (#764) and
// operator-authored patterns (#767) multiply both the rule count and the pattern shapes; issue #787 tracks it. The benchmarks stay
// so the number is checked rather than remembered.
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

func equalFoldRune(a, b rune) bool {
	if a == b {
		return true
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
