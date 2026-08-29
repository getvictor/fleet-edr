package sigma

import (
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
		{"corpus: framework version wildcard", "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/1.2.3/Resources/install.sh", "*Framework.framework/*/Resources/*.sh", true},
		{"corpus: wrong extension", "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/1.2.3/Resources/install.py", "*Framework.framework/*/Resources/*.sh", false},
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
}
