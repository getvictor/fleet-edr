package ssoadmin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// A version the server issued must come back meaning the same thing. This is the whole contract a client relies on: it reads a
// string, sends it back, and the save it guards is the configuration it was actually looking at. Property-based because the pair of
// counters is an input space no table covers, and because the interesting cases are the boundaries a table would not think to
// include: zero on either part (nothing stored yet) and values past a 32-bit counter.
func TestVersionRoundTrips(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := Version{
			OIDC: rapid.Int64Range(0, 1<<62).Draw(t, "oidc"),
			App:  rapid.Int64Range(0, 1<<62).Draw(t, "app"),
		}
		got, err := ParseVersion(want.String())
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

// A version the server did not issue is refused rather than read as "no version". The difference is the whole point: treating an
// unreadable version as absent would turn a client's conditional save into the unconditional overwrite the check exists to prevent,
// and the client would be told its save succeeded safely.
func TestParseVersionRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"one part", "3"},
		{"no separator", "3 4"},
		{"three parts", "1.2.3"},
		{"first part is not a number", "x.2"},
		{"second part is not a number", "1.y"},
		{"first part is negative", "-1.2"},
		{"second part is negative", "1.-2"},
		{"first part is blank", ".2"},
		{"second part is blank", "1."},
		{"padded", " 1.2 "},
		{"hex", "0x1.0x2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseVersion(tc.in)
			assert.Error(t, err)
		})
	}
}

// The two parts are distinguishable in the wire form. A version that collapsed them would let a change to one part pass as the
// other, which is the failure the composite exists to prevent.
func TestVersionDistinguishesItsTwoParts(t *testing.T) {
	t.Parallel()
	assert.NotEqual(t, Version{OIDC: 1, App: 2}.String(), Version{OIDC: 2, App: 1}.String())
}
