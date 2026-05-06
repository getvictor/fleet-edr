package breakglass_test

import (
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/breakglass"
)

// EncodeChallengeState → DecodeChallengeState round-trips the
// SessionData. The HMAC-signed cookie is the integrity gate; a
// regression that lost the gob payload or dropped the signature
// step would either leak SessionData or accept tampered cookies.
func TestChallengeState_RoundTrip(t *testing.T) {
	key := bytes32(0x42)
	sd := webauthn.SessionData{
		Challenge:        "AAA-BBB-CCC",
		RelyingPartyID:   "localhost",
		UserID:           []byte{1, 2, 3, 4, 5, 6, 7, 8},
		UserVerification: protocol.VerificationPreferred,
		Expires:          time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	}

	encoded, err := breakglass.EncodeChallengeState(key, sd)
	require.NoError(t, err)
	assert.Contains(t, encoded, ".", "wire format is sig.payload")

	got, err := breakglass.DecodeChallengeState(key, encoded)
	require.NoError(t, err)
	assert.Equal(t, sd.Challenge, got.Challenge)
	assert.Equal(t, sd.RelyingPartyID, got.RelyingPartyID)
	assert.Equal(t, sd.UserID, got.UserID)
}

// Empty signing key trips a typed error rather than silently
// emitting an unsigned cookie.
func TestEncodeChallengeState_NoKey(t *testing.T) {
	_, err := breakglass.EncodeChallengeState(nil, webauthn.SessionData{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key")
}

// A malformed cookie (no dot separator) returns
// ErrChallengeStateInvalid; same for tampered signature, garbled
// base64, or wrong key.
func TestDecodeChallengeState_FailureModes(t *testing.T) {
	key := bytes32(0x42)
	good, err := breakglass.EncodeChallengeState(key, webauthn.SessionData{
		Challenge: "x", RelyingPartyID: "localhost",
	})
	require.NoError(t, err)

	cases := []struct {
		name string
		raw  string
		key  []byte
	}{
		{"no dot separator", "no-dot-here", key},
		{"empty signature", "." + strings.SplitN(good, ".", 2)[1], key},
		{"empty payload", strings.SplitN(good, ".", 2)[0] + ".", key},
		{"wrong key", good, bytes32(0xFF)},
		{"tampered byte", flipFirstByte(good), key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := breakglass.DecodeChallengeState(tc.key, tc.raw)
			assert.ErrorIs(t, err, breakglass.ErrChallengeStateInvalid)
		})
	}
}

// DecodeChallengeState refuses an empty signing key.
func TestDecodeChallengeState_NoKey(t *testing.T) {
	_, err := breakglass.DecodeChallengeState(nil, "anything.anything")
	require.Error(t, err)
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func flipFirstByte(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	b[0] = '!'
	return string(b)
}
