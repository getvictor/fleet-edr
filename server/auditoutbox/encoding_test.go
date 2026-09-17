package auditoutbox_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// An entry outlives the process that wrote it and is decoded by whatever replica drains it, so what Encode wrote has to be exactly
// what Decode gives back. A round trip over generated events rather than one worked example, because the failure this guards against
// is a field that was never wired into one direction: a missing JSON tag, or a field added to the struct and to Encode but not to
// Decode, which no single hand-written event is likely to touch. Every field the audit row persists is drawn here.
func TestEncodeDecode_RoundTripsEveryFieldTheRowPersists(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		text := rapid.String()
		want := identityapi.AuditEvent{
			Actor: identityapi.PrincipalRef{
				ID:    text.Draw(rt, "actor_id"),
				Type:  identityapi.PrincipalType(text.Draw(rt, "actor_type")),
				Label: text.Draw(rt, "actor_label"),
			},
			Action:     identityapi.AuditAction(text.Draw(rt, "action")),
			TargetType: text.Draw(rt, "target_type"),
			TargetID:   text.Draw(rt, "target_id"),
			TraceID:    text.Draw(rt, "trace_id"),
			RemoteAddr: text.Draw(rt, "remote_addr"),
			Payload: rapid.MapOfN(text, rapid.OneOf(
				rapid.String().AsAny(),
				rapid.Bool().AsAny(),
				// Encoded as a JSON number and decoded as float64, which is the type any reader of a delivered payload sees. Drawn
				// as float64 here so the round trip is over what the format can represent rather than over Go's integer types.
				rapid.Float64().AsAny(),
			), 0, 4).Draw(rt, "payload"),
		}

		entry, err := auditoutbox.Encode(want)
		require.NoError(rt, err)
		require.Equal(rt, auditoutbox.Kind, entry.Kind, "an entry names the encoding that wrote it")

		got, err := auditoutbox.Decode(entry.Payload)
		require.NoError(rt, err)
		if len(want.Payload) == 0 {
			// omitempty drops an empty map, so it comes back nil. Equal on the rest, and nothing was lost.
			want.Payload = nil
		}
		assert.Equal(rt, want, got)
	})
}

// RemoteAddr specifically, because it is the field the response context added (issue #1070) and the one a rolling deploy can drop: a
// replica running the earlier struct decodes this payload and ignores it. This pins that the field is carried under the name both
// sides agree on, rather than only that some round trip succeeds.
func TestEncode_CarriesTheRemoteAddressUnderItsPersistedName(t *testing.T) {
	t.Parallel()
	entry, err := auditoutbox.Encode(identityapi.AuditEvent{
		Action: identityapi.AuditHostContain, TargetType: "host", TargetID: "host-a", RemoteAddr: "203.0.113.5",
	})
	require.NoError(t, err)
	assert.Contains(t, string(entry.Payload), `"remote_addr":"203.0.113.5"`)

	got, err := auditoutbox.Decode(entry.Payload)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.5", got.RemoteAddr)

	// Absent rather than empty when there is none, so an entry from a caller that records no address does not grow a field.
	none, err := auditoutbox.Encode(identityapi.AuditEvent{Action: identityapi.AuditHostRelease})
	require.NoError(t, err)
	assert.NotContains(t, string(none.Payload), "remote_addr")
}
