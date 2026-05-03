package wire

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

func TestDecodeBatch_HappyPath(t *testing.T) {
	body := []byte(`[{"event_id":"e1","host_id":"h","timestamp_ns":100,"event_type":"fork","payload":{"child_pid":1}}]`)
	out, err := DecodeBatch(body)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "e1", out[0].EventID)
	assert.Equal(t, "h", out[0].HostID)
	assert.Equal(t, int64(100), out[0].TimestampNs)
}

func TestDecodeBatch_Empty(t *testing.T) {
	out, err := DecodeBatch([]byte(`[]`))
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestDecodeBatch_Malformed(t *testing.T) {
	_, err := DecodeBatch([]byte(`{not json`))
	require.Error(t, err)
}

func TestEncodeBatch_RoundTrip(t *testing.T) {
	in := []api.Event{
		{
			EventID:     "x",
			HostID:      "h",
			TimestampNs: 1,
			EventType:   "fork",
			Payload:     json.RawMessage(`{"a":1}`),
		},
		{
			EventID:     "y",
			HostID:      "h",
			TimestampNs: 2,
			EventType:   "exec",
			Payload:     json.RawMessage(`{"path":"/bin/sh"}`),
		},
	}
	out, err := EncodeBatch(in)
	require.NoError(t, err)

	got, err := DecodeBatch(out)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, in[0].EventID, got[0].EventID)
	assert.Equal(t, in[1].EventType, got[1].EventType)
}

func TestEncodeBatch_Empty(t *testing.T) {
	out, err := EncodeBatch(nil)
	require.NoError(t, err)
	assert.Equal(t, "null", string(out), "nil slice marshals to null")

	out, err = EncodeBatch([]api.Event{})
	require.NoError(t, err)
	assert.Equal(t, "[]", string(out))
}

// eventGen produces a randomized api.Event suitable for round-trip
// PBT. Field ranges are chosen to cover edge cases (negative pids,
// max-int timestamps) without straying outside the wire contract.
func eventGen() *rapid.Generator[api.Event] {
	return rapid.Custom(func(t *rapid.T) api.Event {
		// Payloads must be valid JSON for json.Unmarshal to round-trip.
		payload := rapid.OneOf(
			rapid.Just(json.RawMessage(`{}`)),
			rapid.Just(json.RawMessage(`{"k":1}`)),
			rapid.Just(json.RawMessage(`null`)),
			rapid.Just(json.RawMessage(`[1,2,3]`)),
			rapid.Just(json.RawMessage(`"string"`)),
			rapid.Just(json.RawMessage(`{"nested":{"deep":[true,null,42]}}`)),
		).Draw(t, "payload")
		return api.Event{
			EventID:      rapid.StringMatching(`[a-zA-Z0-9_-]{1,32}`).Draw(t, "event_id"),
			HostID:       rapid.StringMatching(`[a-zA-Z0-9-]{1,36}`).Draw(t, "host_id"),
			TimestampNs:  rapid.Int64().Draw(t, "ts_ns"),
			IngestedAtNs: rapid.Int64().Draw(t, "ingested_ns"),
			EventType:    rapid.SampledFrom([]string{"fork", "exec", "exit", "open", "network_connect", "dns_query"}).Draw(t, "event_type"),
			Payload:      payload,
		}
	})
}

// TestWire_RoundTripProperty: for any batch of api.Event values,
// DecodeBatch(EncodeBatch(b)) reproduces b. This is the load-bearing
// invariant for the agent contract: the agent and server must agree
// on the JSON wire shape, and any drift surfaces as a round-trip
// mismatch in this property.
func TestWire_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		batch := rapid.SliceOfN(eventGen(), 0, 8).Draw(rt, "batch")
		out, err := EncodeBatch(batch)
		require.NoError(rt, err)

		got, err := DecodeBatch(out)
		require.NoError(rt, err)

		// Empty input (len 0 or nil) decodes to a slice that may be
		// nil rather than empty; treat them as equivalent.
		if len(batch) == 0 && len(got) == 0 {
			return
		}
		require.Len(rt, got, len(batch))
		for i := range batch {
			assert.Equal(rt, batch[i].EventID, got[i].EventID, "event_id at i=%d", i)
			assert.Equal(rt, batch[i].HostID, got[i].HostID, "host_id at i=%d", i)
			assert.Equal(rt, batch[i].TimestampNs, got[i].TimestampNs, "timestamp_ns at i=%d", i)
			assert.Equal(rt, batch[i].EventType, got[i].EventType, "event_type at i=%d", i)
			assert.JSONEq(rt, string(batch[i].Payload), string(got[i].Payload), "payload at i=%d", i)
			// IngestedAtNs uses omitempty: a zero value disappears on
			// the wire and decodes back to zero. Anything non-zero
			// must round-trip exactly.
			if batch[i].IngestedAtNs != 0 {
				assert.Equal(rt, batch[i].IngestedAtNs, got[i].IngestedAtNs, "ingested_at_ns at i=%d", i)
			}
		}
	})
}
