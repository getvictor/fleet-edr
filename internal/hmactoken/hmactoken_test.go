package hmactoken

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func testKey() []byte { return bytes.Repeat([]byte("k"), minKeyLen) }

// flipBase64Char returns a base64url character different from c, so a mutation stays a valid base64url segment yet changes the bytes
// (or their canonical encoding), exercising both the signature-mismatch and the strict-decode-malleability rejection paths.
func flipBase64Char(c byte) byte {
	if c == 'A' {
		return 'B'
	}
	return 'A'
}

func TestNewKey_validation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		key     []byte
		kid     string
		wantErr bool
	}{
		{"ok", testKey(), "v1", false},
		{"short key", make([]byte, minKeyLen-1), "v1", true},
		{"empty kid", testKey(), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, err := NewKey(tc.key, tc.kid)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.kid, k.KID())
		})
	}
}

func TestNewKey_clonesKey(t *testing.T) {
	t.Parallel()
	key := testKey()
	k, err := NewKey(key, "v1")
	require.NoError(t, err)
	tok := k.Seal([]byte("payload"))
	// Mutating the caller's slice must not change the key material under an in-flight verification.
	for i := range key {
		key[i] ^= 0xff
	}
	got, err := k.Open(tok)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
}

// TestSealOpen_roundTrip is the core invariant: any non-empty payload round-trips through Seal then Open unchanged. An empty payload
// is out of contract (every real caller seals non-empty JSON claims); Seal of it produces an empty payload segment, which Open
// correctly rejects as malformed, so the round-trip is exercised over 1+ bytes.
func TestSealOpen_roundTrip(t *testing.T) {
	t.Parallel()
	k, err := NewKey(testKey(), "v1")
	require.NoError(t, err)
	rapid.Check(t, func(rt *rapid.T) {
		payload := rapid.SliceOfN(rapid.Byte(), 1, 256).Draw(rt, "payload")
		got, err := k.Open(k.Seal(payload))
		require.NoError(rt, err)
		assert.Equal(rt, payload, got)
	})
}

// TestOpen_tamperRejected flips any single character of a valid token and asserts Open rejects it. This covers both a MAC mismatch and
// the strict-decode malleability guard (a non-canonical final MAC char must be rejected, not decoded to the same bytes).
func TestOpen_tamperRejected(t *testing.T) {
	t.Parallel()
	k, err := NewKey(testKey(), "v1")
	require.NoError(t, err)
	rapid.Check(t, func(rt *rapid.T) {
		payload := rapid.SliceOfN(rapid.Byte(), 1, 128).Draw(rt, "payload")
		tok := k.Seal(payload)
		idx := rapid.IntRange(0, len(tok)-1).Draw(rt, "idx")
		if tok[idx] == '.' {
			return // flipping a separator changes the segment shape, covered by the malformed table instead
		}
		b := []byte(tok)
		b[idx] = flipBase64Char(b[idx])
		_, err := k.Open(string(b))
		require.Error(rt, err)
	})
}

func TestOpen_malformed(t *testing.T) {
	t.Parallel()
	k, err := NewKey(testKey(), "v1")
	require.NoError(t, err)
	good := k.Seal([]byte(`{"hi":1}`))
	cases := map[string]string{
		"not a token":     "notatoken",
		"two segments":    "v1.abc",
		"wrong version":   "v2" + good[2:],
		"empty payload":   "v1..def",
		"empty mac":       "v1.abc.",
		"extra segment":   "v1.abc.def.ghi",
		"bad base64 mac":  "v1.YWJj.@@@",
		"leading dot":     ".abc.def",
		"mac wrong width": "v1.YWJj.YWJj", // decodes fine but is not sha256.Size bytes
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := k.Open(tok)
			assert.ErrorIs(t, err, ErrMalformed)
		})
	}
}

func TestOpen_wrongKeyIsBadSignature(t *testing.T) {
	t.Parallel()
	signer, err := NewKey(testKey(), "v1")
	require.NoError(t, err)
	tok := signer.Seal([]byte("payload"))

	other, err := NewKey(bytes.Repeat([]byte("z"), minKeyLen), "v1")
	require.NoError(t, err)
	_, err = other.Open(tok)
	assert.ErrorIs(t, err, ErrBadSignature)
}
