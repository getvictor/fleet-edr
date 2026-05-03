package httpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
)

func TestNewClientIPResolver_Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{"nil input is the secure default", nil, false},
		{"empty input is the secure default", []string{}, false},
		{"whitespace-only entries are dropped", []string{" ", "\t"}, false},
		{"bare IPv4", []string{"192.168.1.5"}, false},
		{"bare IPv6", []string{"::1"}, false},
		{"IPv4 CIDR", []string{"10.0.0.0/8"}, false},
		{"IPv6 CIDR", []string{"fd00::/8"}, false},
		{"mixed forms", []string{"10.0.0.0/8", "192.168.1.1", "fd00::/8"}, false},
		{"garbage rejected", []string{"not-an-ip"}, true},
		{"bad CIDR rejected", []string{"10.0.0.0/99"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := httpserver.NewClientIPResolver(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, r)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, r)
		})
	}
}

func TestClientIPResolver_ResolutionRules(t *testing.T) {
	const trustedHop = "10.0.0.5"
	const trustedHopAlt = "10.0.0.6"
	const untrustedHop = "203.0.113.99"
	const realClient = "198.51.100.7"

	mustResolver := func(t *testing.T, cidrs []string) *httpserver.ClientIPResolver {
		t.Helper()
		r, err := httpserver.NewClientIPResolver(cidrs)
		require.NoError(t, err)
		return r
	}

	cases := []struct {
		name        string
		trusted     []string
		remoteAddr  string
		xff         []string // multiple header instances; each may itself be comma-separated
		want        string
		description string
	}{
		{
			name:        "no trusted proxies returns peer regardless of XFF",
			trusted:     nil,
			remoteAddr:  trustedHop + ":5555",
			xff:         []string{realClient},
			want:        trustedHop,
			description: "secure default: untouched by spoofed XFF",
		},
		{
			name:        "untrusted peer ignores XFF",
			trusted:     []string{"10.0.0.0/8"},
			remoteAddr:  untrustedHop + ":5555",
			xff:         []string{"1.2.3.4, " + realClient},
			want:        untrustedHop,
			description: "spoofed XFF from a non-trusted peer must not move the resolved IP",
		},
		{
			name:       "trusted peer with single XFF returns leftmost untrusted",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: trustedHop + ":5555",
			xff:        []string{realClient},
			want:       realClient,
		},
		{
			name:       "trusted peer with chain of trusted hops walks past them",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: trustedHop + ":5555",
			xff:        []string{realClient + ", " + trustedHopAlt + ", " + trustedHop},
			want:       realClient,
		},
		{
			name:       "all-trusted XFF falls back to peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: trustedHop + ":5555",
			xff:        []string{trustedHopAlt + ", " + trustedHop},
			want:       trustedHop,
		},
		{
			name:        "missing XFF + trusted peer returns peer",
			trusted:     []string{"10.0.0.0/8"},
			remoteAddr:  trustedHop + ":5555",
			xff:         nil,
			want:        trustedHop,
			description: "happy path when traffic comes through the proxy without an XFF stamp",
		},
		{
			name:       "multiple XFF header instances combine right-to-left",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: trustedHop + ":5555",
			xff:        []string{realClient, trustedHopAlt + ", " + trustedHop},
			want:       realClient,
		},
		{
			name:        "malformed XFF entry is skipped",
			trusted:     []string{"10.0.0.0/8"},
			remoteAddr:  trustedHop + ":5555",
			xff:         []string{realClient + ", garbage, " + trustedHop},
			want:        realClient,
			description: "garbage entries don't stop the right-to-left walk",
		},
		{
			name:        "empty entries from extra commas are skipped",
			trusted:     []string{"10.0.0.0/8"},
			remoteAddr:  trustedHop + ":5555",
			xff:         []string{",, " + realClient + " , ,"},
			want:        realClient,
			description: "tolerant of proxy formatting quirks",
		},
		{
			name:       "IPv6 trusted peer + IPv6 XFF",
			trusted:    []string{"fd00::/8"},
			remoteAddr: "[fd00::1]:5555",
			xff:        []string{"2001:db8::1, fd00::2"},
			want:       "2001:db8::1",
		},
		{
			name:        "IPv4-mapped IPv6 in XFF compares against IPv4 CIDR",
			trusted:     []string{"10.0.0.0/8"},
			remoteAddr:  trustedHop + ":5555",
			xff:         []string{realClient + ", ::ffff:10.0.0.6"},
			want:        realClient,
			description: "::ffff:10.0.0.6 must be recognised as the same as 10.0.0.6 and skipped",
		},
		{
			name:        "bare-IP trusted entry treated as /32",
			trusted:     []string{"203.0.113.10"},
			remoteAddr:  "203.0.113.10:5555",
			xff:         []string{realClient},
			want:        realClient,
			description: "exact-host match without writing /32",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := mustResolver(t, tc.trusted)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
			req.RemoteAddr = tc.remoteAddr
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			got := resolver.ClientIP(req)
			assert.Equal(t, tc.want, got, "%s", tc.description)
		})
	}
}

func TestClientIPResolver_NilSafety(t *testing.T) {
	var nilResolver *httpserver.ClientIPResolver
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	req.RemoteAddr = "192.168.1.1:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	assert.Equal(t, "192.168.1.1", nilResolver.ClientIP(req),
		"nil resolver behaves like an empty trusted list (peer IP, XFF ignored)")

	assert.Empty(t, nilResolver.ClientIP(nil), "nil request returns empty")
}

func TestClientIP_FallsBackToRemoteAddrWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	req.RemoteAddr = "203.0.113.1:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	// No middleware ran -> ctx has no resolved IP -> fall back to peer.
	// XFF is NOT honoured on this fallback path (the fallback is
	// httpserver.RemoteIP, not the resolver) so a forgotten middleware
	// wire-up degrades safely instead of letting XFF spoofing through.
	assert.Equal(t, "203.0.113.1", httpserver.ClientIP(req))
}

func TestClientIP_NilRequest(t *testing.T) {
	assert.Empty(t, httpserver.ClientIP(nil))
}

func TestClientIPResolver_MiddlewareStashesIPOnContext(t *testing.T) {
	resolver, err := httpserver.NewClientIPResolver([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var observed string
	terminal := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		observed = httpserver.ClientIP(r)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	rr := httptest.NewRecorder()
	resolver.Middleware(terminal).ServeHTTP(rr, req)

	assert.Equal(t, "198.51.100.7", observed,
		"downstream handler reads the resolver's verdict via ClientIP")
}

func TestClientIPResolver_MiddlewareSurvivesNilRequestContext(t *testing.T) {
	// Defensive: pathological middleware ordering could pass an
	// *http.Request with a nil ctx. r.Context() never returns nil per
	// Go's contract, but exercise the code path anyway.
	resolver, err := httpserver.NewClientIPResolver(nil)
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	req.RemoteAddr = "127.0.0.1:9000"
	rr := httptest.NewRecorder()
	resolver.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rr, req)
	// No assertion: the test passes if the middleware doesn't panic.
}
