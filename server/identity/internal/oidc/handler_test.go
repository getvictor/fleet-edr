package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// safeRedirect must drop off-site, scheme-laden, or protocol-relative
// values and fall back to the default UI landing. Pinned here because
// a regression that lets `next=https://evil.example.com` pass through
// is a phishing vector.
func TestSafeRedirect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty -> default", "", "/ui/"},
		{"single-slash same-origin path", "/ui/hosts", "/ui/hosts"},
		{"single-slash with query", "/ui/alerts?status=open", "/ui/alerts?status=open"},
		{"protocol-relative // -> default", "//evil.example.com/path", "/ui/"},
		{"https off-site -> default", "https://evil.example.com", "/ui/"},
		{"http off-site -> default", "http://evil.example.com", "/ui/"},
		{"javascript: scheme -> default", "javascript:alert(1)", "/ui/"},
		{"data: scheme -> default", "data:text/html,<script>", "/ui/"},
		{"non-leading slash -> default", "ui/hosts", "/ui/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, safeRedirect(tc.in))
		})
	}
}

// pathStartsWithSingleSlash distinguishes "/foo" from "//foo". The
// double-slash form is a protocol-relative URL the browser would
// resolve cross-origin; rejecting it is the safeRedirect contract.
func TestPathStartsWithSingleSlash(t *testing.T) {
	assert.True(t, pathStartsWithSingleSlash("/"))
	assert.True(t, pathStartsWithSingleSlash("/foo"))
	assert.False(t, pathStartsWithSingleSlash(""))
	assert.False(t, pathStartsWithSingleSlash("foo"))
	assert.False(t, pathStartsWithSingleSlash("//"))
	assert.False(t, pathStartsWithSingleSlash("//evil"))
}
