package ssoconfig_test

import (
	"crypto/rand"
	"testing"

	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

// TestSealer_roundTrip is the algebraic invariant Open(Seal(x)) == x over an arbitrary byte-slice input space, the PBT shape the
// project prescribes for serialization round-trips. It also pins the two security properties: the sealed blob is never equal to the
// plaintext, and two seals of the same plaintext differ (fresh nonce per Seal).
func TestSealer_roundTrip(t *testing.T) {
	t.Parallel()
	s, err := ssoconfig.NewSealer(newKey(t))
	require.NoError(t, err)

	rapid.Check(t, func(rt *rapid.T) {
		plaintext := rapid.SliceOf(rapid.Byte()).Draw(rt, "plaintext")

		sealed, err := s.Seal(plaintext)
		require.NoError(rt, err)
		assert.NotEqual(rt, plaintext, sealed, "sealed blob must not equal plaintext")

		again, err := s.Seal(plaintext)
		require.NoError(rt, err)
		assert.NotEqual(rt, sealed, again, "two seals of the same plaintext must differ (random nonce)")

		got, err := s.Open(sealed)
		require.NoError(rt, err)
		if len(plaintext) == 0 {
			assert.Empty(rt, got)
		} else {
			assert.Equal(rt, plaintext, got)
		}
	})
}

func TestSealer_openWithWrongKeyFails(t *testing.T) {
	t.Parallel()
	sealer, err := ssoconfig.NewSealer(newKey(t))
	require.NoError(t, err)
	other, err := ssoconfig.NewSealer(newKey(t))
	require.NoError(t, err)

	sealed, err := sealer.Seal([]byte("super-secret-client-secret"))
	require.NoError(t, err)

	_, err = other.Open(sealed)
	require.Error(t, err, "opening with a different key must fail authentication")
}

func TestSealer_openRejectsTamperedOrShort(t *testing.T) {
	t.Parallel()
	s, err := ssoconfig.NewSealer(newKey(t))
	require.NoError(t, err)

	t.Run("too short", func(t *testing.T) {
		t.Parallel()
		_, err := s.Open([]byte{0x01, 0x02})
		require.Error(t, err)
	})

	t.Run("tampered tag", func(t *testing.T) {
		t.Parallel()
		sealed, err := s.Seal([]byte("rotate-me"))
		require.NoError(t, err)
		sealed[len(sealed)-1] ^= 0xFF
		_, err = s.Open(sealed)
		require.Error(t, err)
	})
}

func TestNewSealer_rejectsBadKeyLength(t *testing.T) {
	t.Parallel()
	_, err := ssoconfig.NewSealer([]byte("too-short"))
	require.Error(t, err)
}
