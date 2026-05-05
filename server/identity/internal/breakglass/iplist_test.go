package breakglass_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/breakglass"
)

// NewAllowlist accepts CIDRs, bare IPs, IPv6, and a mixed list. The
// "bare IP normalised to /32 (or /128)" carve-out lets operators
// type "203.0.113.5" without remembering CIDR syntax.
func TestNewAllowlist_AcceptsValidEntries(t *testing.T) {
	cases := [][]string{
		{"203.0.113.0/24"},
		{"203.0.113.5"},
		{"2001:db8::1"},
		{"2001:db8::/32"},
		{"203.0.113.0/24", "10.0.0.0/8", "2001:db8::1"},
		{},   // empty allowlist is permissive
		{""}, // empty entry skipped
	}
	for _, entries := range cases {
		_, err := breakglass.NewAllowlist(entries)
		assert.NoError(t, err, "entries=%v", entries)
	}
}

// Malformed CIDRs / IPs refuse to start. Pinned because a typo at
// boot must surface immediately, not silently leave the surface
// open.
func TestNewAllowlist_RejectsMalformed(t *testing.T) {
	cases := []string{
		"not-an-ip",
		"203.0.113.0/33",
		"203.0.113.5/abc",
	}
	for _, entry := range cases {
		_, err := breakglass.NewAllowlist([]string{entry})
		assert.Error(t, err, "entry=%q", entry)
	}
}

// Allows is the membership check. Empty list returns true; a
// non-matching IP returns false; a matching IP returns true.
func TestAllowlist_Allows(t *testing.T) {
	a, err := breakglass.NewAllowlist([]string{"203.0.113.0/24", "2001:db8::/32"})
	require.NoError(t, err)

	cases := []struct {
		ip     string
		expect bool
	}{
		{"203.0.113.10", true},
		{"203.0.114.10", false},
		{"2001:db8::1", true},
		{"2001:dead::1", false},
		{"127.0.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			assert.Equal(t, tc.expect, a.Allows(net.ParseIP(tc.ip)))
		})
	}

	empty, err := breakglass.NewAllowlist(nil)
	require.NoError(t, err)
	assert.True(t, empty.Allows(net.ParseIP("203.0.113.10")), "empty allowlist passes")
}

// Off-allowlist requests get a generic 404 — same body as an
// unrouted path. Pinned because the spec requires the surface's
// existence to NOT be acknowledged to off-list callers.
func TestAllowlist_Middleware_404sOffList(t *testing.T) {
	a, err := breakglass.NewAllowlist([]string{"203.0.113.0/24"})
	require.NoError(t, err)
	called := false
	wrapped := a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/admin/break-glass", nil)
	r.RemoteAddr = "10.0.0.1:5555" // not on list
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	assert.False(t, called, "off-allowlist must not reach inner handler")
}

// On-list requests pass through.
func TestAllowlist_Middleware_PassesThroughOnList(t *testing.T) {
	a, err := breakglass.NewAllowlist([]string{"127.0.0.0/8"})
	require.NoError(t, err)
	called := false
	wrapped := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/admin/break-glass", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.True(t, called, "on-allowlist must reach inner handler")
}

// Empty allowlist is permissive: every request reaches the inner
// handler. Pinned because the wave-1 default is no allowlist set,
// and a regression that flipped the default to "deny" would brick
// every dev deployment.
func TestAllowlist_Middleware_EmptyPassesAll(t *testing.T) {
	a, err := breakglass.NewAllowlist(nil)
	require.NoError(t, err)
	called := false
	wrapped := a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/admin/break-glass", nil)
	r.RemoteAddr = "10.10.10.10:5555"
	wrapped.ServeHTTP(httptest.NewRecorder(), r)
	assert.True(t, called, "empty allowlist must pass through")
}
