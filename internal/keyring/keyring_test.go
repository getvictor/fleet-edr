package keyring_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/fleetdm/edr/internal/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRoot(t *testing.T) []byte {
	t.Helper()
	root := make([]byte, keyring.MinRootKeyLen)
	_, err := rand.Read(root)
	require.NoError(t, err)
	return root
}

func TestNew_rejectsShortRoot(t *testing.T) {
	cases := []struct {
		name string
		len  int
		ok   bool
	}{
		{"empty", 0, false},
		{"one below floor", keyring.MinRootKeyLen - 1, false},
		{"exactly floor", keyring.MinRootKeyLen, true},
		{"above floor", keyring.MinRootKeyLen + 16, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kr, err := keyring.New(make([]byte, tc.len))
			if tc.ok {
				require.NoError(t, err)
				require.NotNil(t, kr)
				return
			}
			require.Error(t, err)
			assert.Nil(t, kr)
		})
	}
}

// TestLabelConstants_arePinned guards the exported domain-separation labels against an accidental rename or version bump. The bytes
// they derive are baked into every persisted host-token hash and signed session cookie, and both server binaries derive from these
// exact strings, so changing a value here silently invalidates every issued token and breaks cross-binary validation. Treat a failure
// as "this is a deliberate key rotation" and update the literal only with that intent.
func TestLabelConstants_arePinned(t *testing.T) {
	assert.Equal(t, "edr/host-token/sign/v1", keyring.HostTokenSigningLabel)
	assert.Equal(t, "edr/session/signing/v1", keyring.SessionSigningKeyLabel)
}

func TestDerive_isDeterministicPerLabel(t *testing.T) {
	root := newRoot(t)
	kr, err := keyring.New(root)
	require.NoError(t, err)

	a := kr.Derive("edr/host-token/sign/v1")
	b := kr.Derive("edr/host-token/sign/v1")
	assert.Equal(t, a, b, "same label must derive the same key across calls")
	assert.Len(t, a, 32)
}

func TestDerive_distinctLabelsAreIndependent(t *testing.T) {
	root := newRoot(t)
	kr, err := keyring.New(root)
	require.NoError(t, err)

	signing := kr.Derive("edr/host-token/sign/v1")
	session := kr.Derive("edr/session/signing/v1")
	versioned := kr.Derive("edr/host-token/sign/v2")

	assert.NotEqual(t, signing, session, "different purposes must derive different keys")
	assert.NotEqual(t, signing, versioned, "bumping the version must derive a fresh key")
}

func TestDerive_differsAcrossRoots(t *testing.T) {
	krA, err := keyring.New(newRoot(t))
	require.NoError(t, err)
	krB, err := keyring.New(newRoot(t))
	require.NoError(t, err)

	const label = "edr/session/signing/v1"
	assert.NotEqual(t, krA.Derive(label), krB.Derive(label), "different roots must derive different keys for the same label")
}

func TestNew_copiesRoot(t *testing.T) {
	root := newRoot(t)
	kr, err := keyring.New(root)
	require.NoError(t, err)

	before := kr.Derive("edr/session/signing/v1")
	// Mutating the caller's buffer after construction must not change derivation: New holds its own copy.
	for i := range root {
		root[i] ^= 0xFF
	}
	after := kr.Derive("edr/session/signing/v1")
	assert.True(t, bytes.Equal(before, after), "Derive must be unaffected by mutation of the caller's root buffer")
}
