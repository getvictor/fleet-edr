// Package netaddr parses the operator-written address notation this product accepts wherever a configuration names hosts or ranges.
//
// One notation, one parser. Trusted-proxy ranges (server/httpserver) and the addresses that stay reachable during containment
// (issue #1059) are written by the same operator in the same place in their heads, and a second parser would eventually disagree
// with this one about a bare IPv6 literal or an unmasked prefix. Both now call ParsePrefix.
package netaddr

import (
	"net/netip"
	"strings"
)

// MappedBlock is the IPv4-mapped IPv6 block: every IPv4 address has exactly one spelling inside it. An IPv6 range that contains this
// block reaches the whole of IPv4, which a caller judging how broad a range is has to know.
var MappedBlock = netip.MustParsePrefix("::ffff:0.0.0.0/96")

// mappedPrefixBits is where MappedBlock's own prefix ends, so a prefix at least this long lies entirely inside it.
const mappedPrefixBits = 96

// ParsePrefix accepts either a CIDR prefix ("10.0.0.0/8") or a bare address ("192.0.2.7"), and returns it as a prefix.
//
// A bare address becomes a single-address prefix (/32 or /128), so a caller never has to ask which of the two forms it was given.
// A prefix is returned MASKED, so "10.1.2.3/8" and "10.0.0.0/8" are the same value: the host bits an operator left in are not part
// of what the prefix means, and comparing unmasked values would make two spellings of one range look like two ranges.
//
// An IPv4-mapped form ("::ffff:192.0.2.7", "::ffff:192.0.2.0/120") is unmapped to its IPv4 form, so one destination has one
// representation whichever way it was written. This matters to both callers and is not cosmetic. A caller comparing an address
// against a prefix unmaps the address first, so a prefix left mapped would never match anything; and a caller checking how broad a
// range is would read a mapped prefix's bit count as an IPv6 one, under which "::ffff:0:0/96" is a narrow /96 rather than the whole
// of IPv4 that it is.
//
// A mapped prefix is converted only when it lies entirely inside the mapped block (at least 96 bits), which is what makes the
// conversion lossless: its remaining bits are exactly the IPv4 prefix length. A shorter prefix spans address space outside the
// block, so it stays IPv6 and means what it says.
func ParsePrefix(token string) (netip.Prefix, error) {
	if strings.Contains(token, "/") {
		p, err := netip.ParsePrefix(token)
		if err != nil {
			return netip.Prefix{}, err
		}
		p = p.Masked()
		if p.Addr().Is4In6() && p.Bits() >= mappedPrefixBits {
			return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-mappedPrefixBits), nil
		}
		return p, nil
	}
	addr, err := netip.ParseAddr(token)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}
