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
	"strings"
	"unicode"
	"unicode/utf8"
)

// matchWildcard reports whether s matches pattern under Sigma's wildcard rules: `*` stands for any run of characters including the
// empty one, `?` for exactly one character, and everything else is literal.
//
// Comparison is case-insensitive because the Sigma specification defines it that way, and the corpus relies on it: rules write
// 'JavaScript' and '/PlistBuddy' while the values they match arrive in whatever case the host reported.
//
// The implementation walks both strings with a backtracking scan rather than compiling to a regexp. Two reasons, in order of
// weight. First, it allocates nothing, which is the property the hot path needs. Second, Sigma wildcards are not regexp syntax:
// translating them means escaping every regexp metacharacter in the literal runs, and a missed escape turns a literal '.' or '+'
// in a file path into a silent over-match. A path-matching rule that quietly matches more than it says is the failure mode least
// likely to be noticed, because it produces alerts rather than silence.
func matchWildcard(s, pattern string) bool {
	// star tracks the most recent `*` in the pattern and the position in s where it started consuming, so a failed match can
	// backtrack and let that star swallow one more character. This is the standard linear-space glob scan.
	var (
		si, pi int
		starPi = -1
		starSi int
	)
	for si < len(s) {
		pr, pw := decode(pattern, pi)
		switch {
		case pi < len(pattern) && pr == '*':
			starPi, pi = pi, pi+pw
			starSi = si
		case pi < len(pattern) && (pr == '?' || equalFold(s, si, pr)):
			_, sw := decode(s, si)
			si += sw
			pi += pw
		case starPi >= 0:
			// No match here, but a star is open: give it one more character of s and retry the rest of the pattern.
			_, sw := decode(s, starSi)
			starSi += sw
			si, pi = starSi, starPi
			_, w := decode(pattern, starPi)
			pi += w
		default:
			return false
		}
	}
	// s is exhausted; the pattern matches only if what remains is stars.
	for pi < len(pattern) {
		r, w := decode(pattern, pi)
		if r != '*' {
			return false
		}
		pi += w
	}
	return true
}

// decode returns the rune at offset i and its width, or (utf8.RuneError, 1) past the end. Callers guard the end themselves; the
// safe return keeps a malformed tail from panicking.
func decode(s string, i int) (rune, int) {
	if i >= len(s) {
		return utf8.RuneError, 1
	}
	return utf8.DecodeRuneInString(s[i:])
}

// equalFold reports whether the rune at s[si] equals pr ignoring case, without allocating a lowered copy of either string.
func equalFold(s string, si int, pr rune) bool {
	sr, _ := decode(s, si)
	if sr == pr {
		return true
	}
	return unicode.ToLower(sr) == unicode.ToLower(pr)
}

// hasWildcard reports whether a value carries Sigma wildcard syntax. A value without one is compared with a plain case-insensitive
// equality, which is both faster and exactly what Sigma specifies.
func hasWildcard(v string) bool {
	return strings.ContainsAny(v, "*?")
}
