package sensorevent

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestEnvelopeRoundTrip is the wire-format round-trip the testing-strategy matrix requires for a new event field: this
// change adds the `sensor_provider_transition` payload and the extension's `stop_reasons`, and a table could only pin the
// handful of shapes someone thought to write down.
//
// The property is `Unmarshal ∘ Marshal == identity` over the envelope the ingest handler actually receives. It matters
// because the payload is the evidence: a field that silently fails to survive the round trip turns a recorded tamper into
// an event nothing can interpret, and the failure would be invisible at emit time.
func TestEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		provider := rapid.SampledFrom([]string{"content_filter", "dns_proxy"}).Draw(rt, "provider")
		state := rapid.SampledFrom([]string{StateRunning, StateStopped}).Draw(rt, "state")

		payload := map[string]any{"provider": provider, "state": state}
		if state == StateStopped && rapid.Bool().Draw(rt, "has_reason") {
			// The full NEProviderStopReason range, not just the values this build names, because the extension forwards
			// whatever the platform gave it.
			payload["stop_reason"] = rapid.IntRange(0, 20).Draw(rt, "stop_reason")
		}

		env := envelope{
			EventID:     rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`).Draw(rt, "event_id"),
			HostID:      rapid.StringN(1, 64, 64).Draw(rt, "host_id"),
			TimestampNs: rapid.Int64Range(1, 1<<62).Draw(rt, "timestamp_ns"),
			EventType:   EventType,
			Payload:     payload,
		}

		first, err := json.Marshal(env)
		require.NoError(rt, err)
		var decoded envelope
		require.NoError(rt, json.Unmarshal(first, &decoded))

		assert.Equal(rt, env.EventID, decoded.EventID)
		assert.Equal(rt, env.HostID, decoded.HostID)
		assert.Equal(rt, env.TimestampNs, decoded.TimestampNs)
		assert.Equal(rt, env.EventType, decoded.EventType)
		assert.Equal(rt, provider, decoded.Payload["provider"])
		assert.Equal(rt, state, decoded.Payload["state"])

		// JSON has one number type, so an int round-trips as float64. Compare numerically rather than asserting the Go
		// type, and re-marshal to prove the canonical bytes are stable rather than merely field-wise equal.
		if want, ok := payload["stop_reason"].(int); ok {
			got, isNum := decoded.Payload["stop_reason"].(float64)
			require.True(rt, isNum, "stop_reason must survive as a number")
			assert.InDelta(rt, float64(want), got, 0)
		} else {
			assert.NotContains(rt, decoded.Payload, "stop_reason", "a running transition must carry no stop reason")
		}

		second, err := json.Marshal(decoded)
		require.NoError(rt, err)
		assert.JSONEq(rt, string(first), string(second))
	})
}
