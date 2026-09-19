package reachable

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/response/api"
)

// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/an-address-that-would-undo-containment-is-refused
func TestNormalizeRefusesWhatWouldUndoContainment(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc    string
		entry   api.ReachableAddress
		wantErr error
	}{
		{desc: "the IPv4 default route", entry: api.ReachableAddress{CIDR: "0.0.0.0/0"}, wantErr: api.ErrReachableTooBroad},
		{desc: "the IPv6 default route", entry: api.ReachableAddress{CIDR: "::/0"}, wantErr: api.ErrReachableTooBroad},
		{
			// The reason the rule is a floor and not a list of two forbidden prefixes: these two entries are 0.0.0.0/0 written
			// as a pair, and a check that refused only the default route would pass them both.
			desc:    "half of IPv4, which paired with its sibling is the whole of it",
			entry:   api.ReachableAddress{CIDR: "0.0.0.0/1"},
			wantErr: api.ErrReachableTooBroad,
		},
		{desc: "a /7, one bit broader than the floor", entry: api.ReachableAddress{CIDR: "10.0.0.0/7"}, wantErr: api.ErrReachableTooBroad},
		{desc: "an IPv6 /31, one bit broader than its floor", entry: api.ReachableAddress{CIDR: "2001::/31"}, wantErr: api.ErrReachableTooBroad},
		{
			// The IPv4-mapped block, which is every IPv4 address wearing an IPv6 spelling. As a /96 it clears the IPv6 floor of
			// /32 by a mile, so without canonicalisation this is 0.0.0.0/0 written in a way the breadth check waves through.
			desc:    "the whole of IPv4 written as its mapped block",
			entry:   api.ReachableAddress{CIDR: "::ffff:0.0.0.0/96"},
			wantErr: api.ErrReachableTooBroad,
		},
		{
			// And a range one bit wider, which cannot be canonicalised to IPv4 because it reaches outside the block, so it is
			// refused on the containment rather than converted.
			desc:    "a range that contains the mapped block",
			entry:   api.ReachableAddress{CIDR: "::ffff:0.0.0.0/95"},
			wantErr: api.ErrReachableTooBroad,
		},
		{
			// A mapped range that IS expressible as IPv4 is judged as the IPv4 range it is: /104 is an IPv4 /8, at the floor's
			// edge, and /103 is an IPv4 /7, past it.
			desc:    "a mapped range that is broader than the IPv4 floor once read as IPv4",
			entry:   api.ReachableAddress{CIDR: "::ffff:10.0.0.0/103"},
			wantErr: api.ErrReachableTooBroad,
		},
		{desc: "not an address at all", entry: api.ReachableAddress{CIDR: "mdm.example.com"}, wantErr: api.ErrReachableInvalidCIDR},
		{desc: "an address with a port stuck on it", entry: api.ReachableAddress{CIDR: "192.0.2.7:443"}, wantErr: api.ErrReachableInvalidCIDR},
		{desc: "an empty address", entry: api.ReachableAddress{CIDR: ""}, wantErr: api.ErrReachableInvalidCIDR},
		{desc: "a port above the range", entry: api.ReachableAddress{CIDR: "192.0.2.7", Port: 65536}, wantErr: api.ErrReachableInvalidPort},
		{desc: "a negative port", entry: api.ReachableAddress{CIDR: "192.0.2.7", Port: -1}, wantErr: api.ErrReachableInvalidPort},
		{
			desc:    "a transport this build cannot turn into a rule",
			entry:   api.ReachableAddress{CIDR: "192.0.2.7", Transport: "sctp"},
			wantErr: api.ErrReachableInvalidTransport,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			_, err := Normalize([]api.ReachableAddress{tc.entry})
			require.ErrorIs(t, err, tc.wantErr)
			// The operator has to be told WHICH entry, or a set of twenty is a guessing game. Position is one-based because the
			// message is read by a person.
			assert.Contains(t, err.Error(), "address 1")
		})
	}
}

// The floors are where a legitimate operator range still fits, which is the half of the rule a test of refusals alone would not
// pin: a validator that refused everything would pass every case above.
//
// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/an-address-that-would-undo-containment-is-refused
func TestNormalizeAcceptsTheRangesOperatorsActuallyRun(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc  string
		given api.ReachableAddress
		want  api.ReachableAddress
	}{
		{
			desc:  "the largest private IPv4 block, which is the floor itself",
			given: api.ReachableAddress{CIDR: "10.0.0.0/8"},
			want:  api.ReachableAddress{CIDR: "10.0.0.0/8"},
		},
		{
			desc:  "a bare address becomes its single-address prefix",
			given: api.ReachableAddress{CIDR: "192.0.2.7", Note: "MDM server"},
			want:  api.ReachableAddress{CIDR: "192.0.2.7/32", Note: "MDM server"},
		},
		{
			// Host bits an operator left in are not part of what the prefix means. Stored masked, so two spellings of one range
			// are one entry, which is what makes the duplicate check below able to see them.
			desc:  "host bits are masked off",
			given: api.ReachableAddress{CIDR: "10.1.2.3/8"},
			want:  api.ReachableAddress{CIDR: "10.0.0.0/8"},
		},
		{
			desc:  "a bare IPv6 address",
			given: api.ReachableAddress{CIDR: "2001:db8::1"},
			want:  api.ReachableAddress{CIDR: "2001:db8::1/128"},
		},
		{
			desc:  "an IPv6 site allocation at the floor",
			given: api.ReachableAddress{CIDR: "2001:db8::/32"},
			want:  api.ReachableAddress{CIDR: "2001:db8::/32"},
		},
		{
			// A mapped range inside the block is the IPv4 range it is, so it is judged and stored as one. Without this it would
			// be a second spelling of an IPv4 destination that the duplicate check could not see.
			desc:  "a mapped range becomes the IPv4 range it is",
			given: api.ReachableAddress{CIDR: "::ffff:10.0.0.0/104"},
			want:  api.ReachableAddress{CIDR: "10.0.0.0/8"},
		},
		{
			desc:  "a mapped host becomes the IPv4 address it is",
			given: api.ReachableAddress{CIDR: "::ffff:192.0.2.7/128"},
			want:  api.ReachableAddress{CIDR: "192.0.2.7/32"},
		},
		{
			desc:  "a port and transport are kept, and the transport is folded to lower case",
			given: api.ReachableAddress{CIDR: "192.0.2.7", Port: 443, Transport: "TCP"},
			want:  api.ReachableAddress{CIDR: "192.0.2.7/32", Port: 443, Transport: api.TransportTCP},
		},
		{
			desc:  "surrounding space an operator pasted in is not part of the address",
			given: api.ReachableAddress{CIDR: "  192.0.2.7  ", Note: "  share  "},
			want:  api.ReachableAddress{CIDR: "192.0.2.7/32", Note: "share"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			got, err := Normalize([]api.ReachableAddress{tc.given})
			require.NoError(t, err)
			assert.Equal(t, []api.ReachableAddress{tc.want}, got)
		})
	}
}

// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/an-address-that-would-undo-containment-is-refused
func TestNormalizeRefusesOneDestinationWrittenTwice(t *testing.T) {
	t.Parallel()
	// Refused rather than collapsed: two notes on one destination are two operators' claims about one filter rule, and keeping
	// either silently discards the other's.
	duplicates := []struct {
		desc  string
		given []api.ReachableAddress
	}{
		{
			desc: "two spellings of one range",
			given: []api.ReachableAddress{
				{CIDR: "10.0.0.0/8", Note: "corporate"},
				{CIDR: "10.1.2.3/8", Note: "the other one"},
			},
		},
		{
			// Across address families: an IPv4 destination and its IPv4-mapped spelling are one destination and one rule.
			desc: "an address and its mapped spelling",
			given: []api.ReachableAddress{
				{CIDR: "192.0.2.7", Note: "MDM"},
				{CIDR: "::ffff:192.0.2.7/128", Note: "MDM again"},
			},
		},
	}
	for _, tc := range duplicates {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			_, err := Normalize(tc.given)
			require.ErrorIs(t, err, api.ErrReachableDuplicate)
			assert.Contains(t, err.Error(), "address 2")
			assert.Contains(t, err.Error(), "address 1", "the operator is told which pair collided, not just that one did")
		})
	}

	t.Run("the port and transport are part of the destination", func(t *testing.T) {
		t.Parallel()
		// So the same address on two ports is two entries rather than a duplicate.
		got, err := Normalize([]api.ReachableAddress{
			{CIDR: "192.0.2.7", Port: 443, Transport: api.TransportTCP},
			{CIDR: "192.0.2.7", Port: 445, Transport: api.TransportTCP},
			{CIDR: "192.0.2.7", Port: 443, Transport: api.TransportUDP},
		})
		require.NoError(t, err)
		assert.Len(t, got, 3)
	})
}

func TestNormalizeCapsTheSet(t *testing.T) {
	t.Parallel()
	atCap := make([]api.ReachableAddress, 0, api.MaxReachableAddresses+1)
	for i := range api.MaxReachableAddresses + 1 {
		atCap = append(atCap, api.ReachableAddress{CIDR: fmt.Sprintf("192.0.2.%d", i)})
	}
	_, err := Normalize(atCap)
	require.ErrorIs(t, err, api.ErrReachableTooMany)
	// Named like every other refusal, so a long list can be trimmed from a known point rather than bisected.
	assert.Contains(t, err.Error(), fmt.Sprintf("address %d", api.MaxReachableAddresses+1))

	// One below the cap is stored, so the cap is a boundary and not an off-by-one refusing the last legitimate entry.
	got, err := Normalize(atCap[:api.MaxReachableAddresses])
	require.NoError(t, err)
	assert.Len(t, got, api.MaxReachableAddresses)
}

func TestNormalizeRefusesANoteTooLongToStore(t *testing.T) {
	t.Parallel()
	long := make([]rune, api.MaxReachableNoteLength+1)
	for i := range long {
		long[i] = 'ä' // multi-byte: the cap is in runes, so a byte-counting check would refuse a note half this length.
	}
	_, err := Normalize([]api.ReachableAddress{{CIDR: "192.0.2.7", Note: string(long)}})
	require.ErrorIs(t, err, api.ErrReachableNoteTooLong)

	got, err := Normalize([]api.ReachableAddress{{CIDR: "192.0.2.7", Note: string(long[:api.MaxReachableNoteLength])}})
	require.NoError(t, err)
	assert.Len(t, []rune(got[0].Note), api.MaxReachableNoteLength)
}

// An empty set is what a deployment starts at and what an operator returns to when they remove the last address, so it is not a
// refusal. The distinction matters: refusing it would leave an operator unable to take back what they granted.
func TestNormalizeAcceptsAnEmptySet(t *testing.T) {
	t.Parallel()
	got, err := Normalize(nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}
