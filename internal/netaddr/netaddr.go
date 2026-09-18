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

// ParsePrefix accepts either a CIDR prefix ("10.0.0.0/8") or a bare address ("192.0.2.7"), and returns it as a prefix.
//
// A bare address becomes a single-address prefix (/32 or /128), so a caller never has to ask which of the two forms it was given.
// A prefix is returned MASKED, so "10.1.2.3/8" and "10.0.0.0/8" are the same value: the host bits an operator left in are not part
// of what the prefix means, and comparing unmasked values would make two spellings of one range look like two ranges.
//
// An IPv4-mapped IPv6 literal ("::ffff:192.0.2.7") is unmapped to its IPv4 form, so one address has one representation whichever
// way it was written. Mapped forms are only unmapped for a BARE address: a prefix carries its own family in the bit count, and
// rewriting the family under it would change what the operator wrote.
func ParsePrefix(token string) (netip.Prefix, error) {
	if strings.Contains(token, "/") {
		p, err := netip.ParsePrefix(token)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
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
