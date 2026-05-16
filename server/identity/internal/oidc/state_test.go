package oidc_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/oidc"
)

var testKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes

// Round-trip: encode then decode returns identical fields.
func TestStateCookie_RoundTrip(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cookie, err := oidc.EncodeStateClaim(testKey, "STATE", "NONCE", "CODEVERIFIER", "/ui/", now)
	require.NoError(t, err)

	got, err := oidc.DecodeStateClaim(testKey, cookie, now, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "STATE", got.State)
	assert.Equal(t, "NONCE", got.Nonce)
	assert.Equal(t, "CODEVERIFIER", got.CodeVerifier)
	assert.Equal(t, "/ui/", got.Redirect)
}

// A cookie issued more than ttl ago is rejected as expired even if the signature is valid. Bounds the per-flow window to the
// configured TTL regardless of how long the browser kept the cookie.
func TestStateCookie_Expired(t *testing.T) {
	issued := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cookie, err := oidc.EncodeStateClaim(testKey, "S", "N", "V", "/ui/", issued)
	require.NoError(t, err)

	tooLate := issued.Add(6 * time.Minute)
	_, err = oidc.DecodeStateClaim(testKey, cookie, tooLate, 5*time.Minute)
	require.ErrorIs(t, err, oidc.ErrInvalidStateCookie,
		"expiry must wrap ErrInvalidStateCookie")
	assert.Contains(t, err.Error(), "expired")
}

// A cookie with a tampered signature does not decode. The constant-
// time comparison rejects single-byte tweaks; the test confirms.
func TestStateCookie_BadSignature(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cookie, err := oidc.EncodeStateClaim(testKey, "S", "N", "V", "/ui/", now)
	require.NoError(t, err)

	// Flip the last char of the signature segment.
	parts := strings.Split(cookie, ".")
	require.Len(t, parts, 2)
	last := parts[1]
	bad := parts[0] + "." + flipLast(last)

	_, err = oidc.DecodeStateClaim(testKey, bad, now, 5*time.Minute)
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrInvalidStateCookie)
}

// Decoding with the wrong key always fails. Catches a key-rotation bug
// where the verifier shipped without re-issuing the cookies.
func TestStateCookie_WrongKey(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cookie, err := oidc.EncodeStateClaim(testKey, "S", "N", "V", "/ui/", now)
	require.NoError(t, err)

	otherKey := append([]byte{}, testKey...)
	otherKey[0] ^= 0xff
	_, err = oidc.DecodeStateClaim(otherKey, cookie, now, 5*time.Minute)
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrInvalidStateCookie)
}

// A malformed cookie (no dot separator) returns the same error class. The handler maps every ErrInvalidStateCookie to one wire-format
// 400 regardless of root cause, but the test pins the malformed-shape branch so a regression on the parser doesn't fall through
// silently.
func TestStateCookie_Malformed(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	_, err := oidc.DecodeStateClaim(testKey, "no-dot-here", now, 5*time.Minute)
	require.ErrorIs(t, err, oidc.ErrInvalidStateCookie)
	assert.Contains(t, err.Error(), "malformed")
}

// Empty payload field rejects: the cookie's structure decodes but the
// claim is missing required values. Pins the second-pass validation.
func TestStateCookie_MissingClaim(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cookie, err := oidc.EncodeStateClaim(testKey, "", "N", "V", "/ui/", now)
	require.NoError(t, err)

	_, err = oidc.DecodeStateClaim(testKey, cookie, now, 5*time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required claim")
}

// flipLast returns s with its last byte XOR'd; useful for "tamper one
// bit and confirm rejection" tests.
func flipLast(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	b[len(b)-1] ^= 0x01
	if b[len(b)-1] == 0 || b[len(b)-1] == '.' {
		// Keep the result legal base64url URL-safe; flip a different bit.
		b[len(b)-1] ^= 0x02
	}
	return string(b)
}
