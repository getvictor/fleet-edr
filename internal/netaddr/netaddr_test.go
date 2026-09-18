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
		{
			// Inside the mapped block, so the remaining bits ARE the IPv4 prefix length and the conversion loses nothing. Left
			// mapped, this would never match an address (callers unmap the address first) and its /104 would read as a narrow
			// IPv6 range rather than the IPv4 /8 it is.
			desc:  "a mapped range becomes the IPv4 range it is",
			given: "::ffff:10.0.0.0/104",
			want:  "10.0.0.0/8",
		},
		{desc: "a mapped host prefix becomes an IPv4 /32", given: "::ffff:192.0.2.7/128", want: "192.0.2.7/32"},
		{desc: "the mapped block itself is the whole of IPv4", given: "::ffff:0.0.0.0/96", want: "0.0.0.0/0"},
		{
			// One bit wider reaches outside the block, so it is not an IPv4 range and is left as the IPv6 range it is. A caller
			// judging breadth has to notice separately that it CONTAINS every IPv4 address.
			desc:  "a range wider than the block stays IPv6",
			given: "::ffff:0.0.0.0/95",
			want:  "::fffe:0:0/95",
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
	cases := []struct {
		desc  string
		given string
	}{
		// Named rather than using the input as the label: Go turns an empty label into an ordinal like #00, so the one case whose
		// input is empty would be the one case a failure could not identify.
		{desc: "an empty string", given: ""},
		{desc: "a word", given: "not-an-address"},
		{desc: "a host name", given: "example.com"},
		{desc: "an address with a port", given: "192.0.2.7:443"},
		{desc: "an IPv4 prefix over 32 bits", given: "10.0.0.0/33"},
		{desc: "a prefix with no bit count", given: "10.0.0.0/"},
		{desc: "an IPv6 prefix over 128 bits", given: "2001:db8::/129"},
		{desc: "two bit counts", given: "192.0.2.0/8/8"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			_, err := netaddr.ParsePrefix(tc.given)
			require.Error(t, err)
		})
	}
}

// FuzzParsePrefix pins the invariants every caller leans on, over inputs no table would think to write.
//
// Worth fuzzing despite the input being operator-written rather than hostile: the value decides which peers are trusted and which
// destinations a contained host can reach, and the invariants are subtle enough that a real bug already slipped through them (an
// IPv4-mapped CIDR stayed IPv6, which made one destination two and made a /96 spanning all of IPv4 look narrow).
//
// The properties, and what breaks without each:
//
//   - A result is CANONICAL: parsing its own string yields itself. Without it, one destination has two spellings and a duplicate
//     check cannot see them.
//   - A result is MASKED: no host bits survive. Two spellings of one range would otherwise compare unequal.
//   - A result's bit count is within its family, and a 4-in-6 address never survives as IPv6, so a caller judging breadth by bits is
//     judging the family it thinks it is.
func FuzzParsePrefix(f *testing.F) {
	for _, seed := range []string{
		"10.0.0.0/8", "10.1.2.3/8", "192.0.2.7", "2001:db8::1", "::ffff:192.0.2.7", "::ffff:10.0.0.0/104",
		"::ffff:0.0.0.0/96", "::ffff:0.0.0.0/95", "0.0.0.0/0", "::/0", "", "not-an-address", "10.0.0.0/33",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		got, err := netaddr.ParsePrefix(token)
		if err != nil {
			return // a refusal is always allowed; what matters is what an acceptance guarantees
		}
		require.True(t, got.IsValid(), "accepted %q and returned an invalid prefix", token)

		again, err := netaddr.ParsePrefix(got.String())
		require.NoError(t, err, "accepted %q as %q, which it then refuses", token, got)
		require.Equal(t, got, again, "%q parsed to %q, which parses to something else again", token, got)

		require.Equal(t, got, got.Masked(), "accepted %q as %q, which still carries host bits", token, got)
		require.False(t, got.Addr().Is4In6(), "accepted %q as a mapped address %q, which a caller would read as IPv6", token, got)
		if got.Addr().Is4() {
			require.LessOrEqual(t, got.Bits(), 32, "IPv4 prefix %q has more bits than the family has", got)
		} else {
			require.LessOrEqual(t, got.Bits(), 128, "IPv6 prefix %q has more bits than the family has", got)
		}
	})
}
