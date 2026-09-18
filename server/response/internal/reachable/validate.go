// Package reachable stores the addresses a contained host may still reach and serves the operator surface that edits them
// (issue #1059). The set is deployment-wide, versioned as a whole, and delivered with each host's containment state.
package reachable

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/fleetdm/edr/internal/netaddr"
	"github.com/fleetdm/edr/server/response/api"
)

// Normalize validates a proposed set and returns it in canonical form, ready to store.
//
// Validation and canonicalisation are one pass on purpose. Every check below needs the parsed prefix, and a design that validated
// the operator's spelling and stored it verbatim would store two spellings of one destination ("10.0.0.0/8" and "10.1.2.3/8") that
// the duplicate check could not see and a host would turn into two identical filter rules.
//
// The whole set is rejected when any entry is, rather than the bad entries being dropped. A responder who asked for four
// destinations and silently got three would find out during an incident.
func Normalize(addresses []api.ReachableAddress) ([]api.ReachableAddress, error) {
	if len(addresses) > api.MaxReachableAddresses {
		return nil, fmt.Errorf("%w: %d given, at most %d", api.ErrReachableTooMany, len(addresses), api.MaxReachableAddresses)
	}
	out := make([]api.ReachableAddress, 0, len(addresses))
	seen := make(map[api.ReachableAddress]int, len(addresses))
	for i, entry := range addresses {
		normalized, err := normalizeOne(entry)
		if err != nil {
			return nil, fmt.Errorf("address %d (%q): %w", i+1, entry.CIDR, err)
		}
		// Keyed on the whole entry minus the note, so the same destination with two different labels is still one rule and is
		// reported rather than stored twice.
		key := normalized
		key.Note = ""
		if first, dup := seen[key]; dup {
			return nil, fmt.Errorf("address %d (%q): %w: it is also address %d", i+1, entry.CIDR, api.ErrReachableDuplicate, first+1)
		}
		seen[key] = i
		out = append(out, normalized)
	}
	return out, nil
}

func normalizeOne(entry api.ReachableAddress) (api.ReachableAddress, error) {
	prefix, err := netaddr.ParsePrefix(strings.TrimSpace(entry.CIDR))
	if err != nil {
		return api.ReachableAddress{}, fmt.Errorf("%w", api.ErrReachableInvalidCIDR)
	}
	if err := checkBreadth(prefix); err != nil {
		return api.ReachableAddress{}, err
	}
	if entry.Port < 0 || entry.Port > 65535 {
		return api.ReachableAddress{}, fmt.Errorf("%w: %d", api.ErrReachableInvalidPort, entry.Port)
	}
	transport := strings.ToLower(strings.TrimSpace(entry.Transport))
	if transport != "" && transport != api.TransportTCP && transport != api.TransportUDP {
		return api.ReachableAddress{}, fmt.Errorf("%w: %q", api.ErrReachableInvalidTransport, entry.Transport)
	}
	note := strings.TrimSpace(entry.Note)
	if utf8.RuneCountInString(note) > api.MaxReachableNoteLength {
		return api.ReachableAddress{}, api.ErrReachableNoteTooLong
	}
	return api.ReachableAddress{CIDR: prefix.String(), Port: entry.Port, Transport: transport, Note: note}, nil
}

// checkBreadth refuses a range broad enough to make containment meaningless. See MinReachablePrefixBitsV4 for why the floors sit
// where they do, and why a floor rather than a list of forbidden prefixes.
func checkBreadth(prefix netip.Prefix) error {
	floor := api.MinReachablePrefixBitsV4
	if prefix.Addr().Is6() {
		floor = api.MinReachablePrefixBitsV6
	}
	if prefix.Bits() < floor {
		return fmt.Errorf("%w: /%d reaches more than the /%d limit for this address family", api.ErrReachableTooBroad,
			prefix.Bits(), floor)
	}
	return nil
}
