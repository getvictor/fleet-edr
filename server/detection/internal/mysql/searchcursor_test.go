package mysql

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// TestCursor_RoundTripProperty: decode(encode(c)) == c for any (fork_time_ns, id). The pagination contract must not lose or mangle
// the keyset position, including negatives and the int64 extremes.
func TestCursor_RoundTripProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		c := searchCursor{
			forkTimeNs: rapid.Int64().Draw(rt, "fork"),
			id:         rapid.Int64().Draw(rt, "id"),
		}
		got, err := decodeCursor(encodeCursor(c))
		require.NoError(rt, err)
		assert.Equal(rt, c, got)
	})
}

func TestDecodeCursor_Malformed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		token string
	}{
		{"not base64", "not!base64!"},
		{"no separator", b64("1234567890")},
		{"non-numeric fork", b64("abc:5")},
		{"non-numeric id", b64("100:xyz")},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeCursor(tc.token)
			assert.ErrorIs(t, err, api.ErrInvalidCursor, "malformed cursor must wrap ErrInvalidCursor")
		})
	}
}

// b64 wraps a raw cursor body so a test can craft a well-formed base64url token with malformed contents.
func b64(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}
