package netaddr_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/netaddr"
)

func TestParsePrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc  string
		given string
		want  string
	}{
		{desc: "a CIDR range is kept", given: "10.0.0.0/8", want: "10.0.0.0/8"},
		{
			// Load-bearing for every caller that compares two prefixes: unmasked, "10.1.2.3/8" and "10.0.0.0/8" are different
			// values for one range, so a trusted-proxy list would hold it twice and a reachable-address set could not tell that
			// an operator had written the same destination twice.
			desc:  "host bits an operator left in are masked off",
			given: "10.1.2.3/8",
			want:  "10.0.0.0/8",
		},
		{desc: "a bare IPv4 address is its own single-address prefix", given: "192.0.2.7", want: "192.0.2.7/32"},
		{desc: "a bare IPv6 address is a /128", given: "2001:db8::1", want: "2001:db8::1/128"},
		{desc: "an IPv6 range is kept and masked", given: "2001:db8:1234::/32", want: "2001:db8::/32"},
		{
			// One address has one representation whichever way it was written, so a mapped literal and its IPv4 form compare
			// equal rather than reading as two destinations.
			desc:  "an IPv4-mapped IPv6 literal is unmapped",
			given: "::ffff:192.0.2.7",
			want:  "192.0.2.7/32",
		},
		{desc: "the IPv4 default route parses, and is the caller's to refuse", given: "0.0.0.0/0", want: "0.0.0.0/0"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			got, err := netaddr.ParsePrefix(tc.given)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}

func TestParsePrefixRejects(t *testing.T) {
	t.Parallel()
	for _, token := range []string{"", "not-an-address", "example.com", "192.0.2.7:443", "10.0.0.0/33", "10.0.0.0/",
		"2001:db8::/129", "192.0.2.0/8/8"} {
		t.Run(token, func(t *testing.T) {
			t.Parallel()
			_, err := netaddr.ParsePrefix(token)
			require.Error(t, err)
		})
	}
}
