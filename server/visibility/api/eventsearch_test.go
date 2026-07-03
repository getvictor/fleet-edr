package api_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/visibility/api"
)

// encodeRaw wraps a raw cursor body so a test can craft a well-formed base64url token carrying malformed contents.
func encodeRaw(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// TestEventCursor_RoundTripProperty: DecodeEventCursor(EncodeEventCursor(c)) == c for any (timestamp_ns, event_id), including an
// event_id containing ':' (the raw form joins on the first colon only) and the int64 extremes. The cursor is an opaque wire token
// exposed to API clients, so its codec gets a dedicated round-trip test.
func TestEventCursor_RoundTripProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		c := api.EventCursor{
			TimestampNs: rapid.Int64().Draw(rt, "ts"),
			EventID:     rapid.StringMatching(`[ -~]{0,40}`).Draw(rt, "event_id"),
		}
		got, err := api.DecodeEventCursor(api.EncodeEventCursor(c))
		require.NoError(rt, err)
		assert.Equal(rt, c, got)
	})
}

func TestDecodeEventCursor_Malformed(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, token string }{
		{"not base64", "not!base64!"},
		{"no separator", encodeRaw("1234567890")},
		{"non-numeric timestamp", encodeRaw("abc:evt-1")},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := api.DecodeEventCursor(tc.token)
			assert.ErrorIs(t, err, api.ErrInvalidEventCursor)
		})
	}
}

func TestArtifactField(t *testing.T) {
	t.Parallel()
	cases := []struct {
		eventType string
		field     string
		ok        bool
	}{
		{"network_connect", "remote_address", true},
		{"dns_query", "query_name", true},
		{"exec", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			t.Parallel()
			field, ok := api.ArtifactField(tc.eventType)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.field, field)
		})
	}
}
