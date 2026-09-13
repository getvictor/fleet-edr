package sensorevent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// captureEmitter records what an emit call was handed, so the tests assert on the wire shape rather than on a mock's
// expectations.
type captureEmitter struct {
	calls []struct {
		eventType string
		payload   map[string]any
	}
	err error
}

func (c *captureEmitter) emit(_ context.Context, eventType string, payload map[string]any) error {
	c.calls = append(c.calls, struct {
		eventType string
		payload   map[string]any
	}{eventType, payload})
	return c.err
}

// TestEmitRecoveryFailedCarriesTheOperatorFacingFields pins what the server needs to raise an actionable finding: which
// provider, which failure shape, and that the repair was genuinely attempted.
func TestEmitRecoveryFailedCarriesTheOperatorFacingFields(t *testing.T) {
	t.Parallel()
	var c captureEmitter
	require.NoError(t, EmitRecoveryFailed(context.Background(), c.emit, "content_filter", "network_extension", "enable_failed", 3))

	require.Len(t, c.calls, 1)
	assert.Equal(t, RecoveryFailedEventType, c.calls[0].eventType)
	assert.Equal(t, map[string]any{
		"provider":  "content_filter",
		"component": "network_extension",
		"outcome":   "enable_failed",
		"attempts":  3,
	}, c.calls[0].payload)
}

// TestEmitRecoveryFailedOmitsAnUnknownComponent: the component is additive on a wire older agents already speak, so a caller
// that cannot name one still emits. The KEY must be absent rather than present and empty, because the server reads absence as
// "this agent does not report it" and would otherwise have to treat an empty string as the same thing.
func TestEmitRecoveryFailedOmitsAnUnknownComponent(t *testing.T) {
	t.Parallel()
	var c captureEmitter
	require.NoError(t, EmitRecoveryFailed(context.Background(), c.emit, "content_filter", "", "enable_failed", 3))

	require.Len(t, c.calls, 1)
	assert.NotContains(t, c.calls[0].payload, "component")
	assert.Equal(t, "content_filter", c.calls[0].payload["provider"])
}

// TestEmitRecoveryFailedRejectsAnUnactionableRecord covers the inputs that would produce a finding nobody can act on. The
// server derives the alert's dedup subject from the provider, so an empty one would also make every such event collapse
// onto a single alert.
func TestEmitRecoveryFailedRejectsAnUnactionableRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		provider string
		outcome  string
	}{
		{"no provider", "", "enable_failed"},
		{"no outcome", "content_filter", ""},
		{"neither", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var c captureEmitter
			require.Error(t, EmitRecoveryFailed(context.Background(), c.emit, tc.provider, "network_extension", tc.outcome, 3))
			assert.Empty(t, c.calls, "nothing may be emitted for a record the server cannot act on")
		})
	}
}

// TestEmitRecoveryFailedWithNoEmitterIsANoOp mirrors how the rest of this package treats a missing sink: a build wired
// without the queue must not error on every escalation.
func TestEmitRecoveryFailedWithNoEmitterIsANoOp(t *testing.T) {
	t.Parallel()
	assert.NoError(t, EmitRecoveryFailed(context.Background(), nil, "content_filter", "network_extension", "enable_failed", 3))
}

// TestEmitRecoveryFailedSurfacesTheEmitError pins that a queue rejection reaches the caller. The caller logs it rather
// than retrying, which is only a defensible choice if it can see the failure at all.
func TestEmitRecoveryFailedSurfacesTheEmitError(t *testing.T) {
	t.Parallel()
	c := captureEmitter{err: assert.AnError}
	assert.ErrorIs(t, EmitRecoveryFailed(context.Background(), c.emit, "content_filter", "network_extension", "enable_failed", 3), assert.AnError)
}

// TestRecoveryFailedEnvelopeRoundTrip is the wire-format round-trip the testing-strategy matrix requires for a new event
// type, and the sibling of TestEnvelopeRoundTrip for the transition payload.
//
// The property is `Unmarshal ∘ Marshal == identity` over the envelope the ingest handler actually receives. It earns its
// place because this payload mixes a number with strings: attempts is the one field where JSON's single number type could
// quietly hand the server a float where it expected an integer, and the failure would be invisible at emit time.
func TestRecoveryFailedEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		provider := rapid.SampledFrom([]string{"content_filter", "dns_proxy"}).Draw(rt, "provider")
		outcome := rapid.SampledFrom([]string{"enable_failed", "enable_ineffective"}).Draw(rt, "outcome")
		attempts := rapid.IntRange(1, 10).Draw(rt, "attempts")
		// Includes the empty component, the older-agent shape, so the round trip covers the field being absent as well as set.
		component := rapid.SampledFrom([]string{"", "network_extension", "endpoint_security_extension"}).Draw(rt, "component")

		var c captureEmitter
		require.NoError(t, EmitRecoveryFailed(context.Background(), c.emit, provider, component, outcome, attempts))

		encoded, err := json.Marshal(envelope{
			EventID:     "e1",
			HostID:      "host-a",
			TimestampNs: 1,
			EventType:   RecoveryFailedEventType,
			Payload:     c.calls[0].payload,
		})
		require.NoError(rt, err)

		var got struct {
			EventType string `json:"event_type"`
			Payload   struct {
				Provider string `json:"provider"`
				Outcome  string `json:"outcome"`
				Attempts int    `json:"attempts"`
			} `json:"payload"`
		}
		require.NoError(rt, json.Unmarshal(encoded, &got))
		assert.Equal(rt, RecoveryFailedEventType, got.EventType)
		assert.Equal(rt, provider, got.Payload.Provider)
		assert.Equal(rt, outcome, got.Payload.Outcome)
		assert.Equal(rt, attempts, got.Payload.Attempts, "the attempt count must survive as an integer")
	})
}
