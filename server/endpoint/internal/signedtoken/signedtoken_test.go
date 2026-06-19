package signedtoken

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// testKey returns a deterministic 32-byte key. Not random: tests must be reproducible, and the key value is irrelevant to the
// properties under test.
func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// flipBase64Char returns a base64url character different from c, so a mutation stays a valid base64url segment (exercising the
// signature-mismatch path rather than the decode-error path).
func flipBase64Char(c byte) byte {
	if c == 'A' {
		return 'B'
	}
	return 'A'
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		key     []byte
		kid     string
		wantErr bool
	}{
		{"ok", testKey(), "v1", false},
		{"short key", make([]byte, 31), "v1", true},
		{"empty kid", testKey(), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tc.key, tc.kid)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestSigner_RoundTrip is the core property: for any host id, epoch, and positive ttl, a minted token verifies within its window and
// returns the exact claims, and is rejected the instant it reaches expiry.
func TestSigner_RoundTrip(t *testing.T) {
	t.Parallel()
	s, err := New(testKey(), "v1")
	require.NoError(t, err)
	now := time.Unix(1_700_000_000, 0).UTC()
	rapid.Check(t, func(rt *rapid.T) {
		hostID := rapid.StringMatching(`[0-9A-Fa-f-]{1,64}`).Draw(rt, "hostID")
		epoch := rapid.Int64Range(0, 1_000_000).Draw(rt, "epoch")
		ttl := time.Duration(rapid.Int64Range(1, 86_400).Draw(rt, "ttlSec")) * time.Second

		tok, exp, err := s.Mint(hostID, epoch, ttl, now)
		require.NoError(rt, err)
		assert.Equal(rt, exp, now.Add(ttl).Truncate(time.Second), "returned expiry is now+ttl")

		claims, err := s.Verify(tok, now.Add(ttl/2))
		require.NoError(rt, err, "verifies within window")
		assert.Equal(rt, hostID, claims.HostID)
		assert.Equal(rt, epoch, claims.Epoch)
		assert.Equal(rt, "v1", claims.KeyID)
		assert.Equal(rt, now.Unix(), claims.IssuedAt)
		assert.Equal(rt, now.Add(ttl).Unix(), claims.ExpiresAt)

		_, err = s.Verify(tok, now.Add(ttl))
		assert.ErrorIs(rt, err, ErrExpired, "rejected exactly at expiry")
	})
}

// spec:agent-enrollment/host-tokens-are-self-validating-signed-tokens/a-tampered-or-expired-token-is-rejected
//
// TestSigner_TamperRejected: flipping any single byte of a valid token makes Verify fail. Whether the failure is a decode error or a
// signature mismatch depends on which segment was hit; the property is only that no tampered token verifies.
func TestSigner_TamperRejected(t *testing.T) {
	t.Parallel()
	s, err := New(testKey(), "v1")
	require.NoError(t, err)
	now := time.Unix(1_700_000_000, 0).UTC()
	rapid.Check(t, func(rt *rapid.T) {
		hostID := rapid.StringMatching(`[a-z0-9]{1,32}`).Draw(rt, "hostID")
		tok, _, err := s.Mint(hostID, 0, time.Hour, now)
		require.NoError(rt, err)

		idx := rapid.IntRange(0, len(tok)-1).Draw(rt, "idx")
		repl := byte('A')
		if tok[idx] == 'A' {
			repl = 'B'
		}
		tampered := tok[:idx] + string(repl) + tok[idx+1:]
		if tampered == tok {
			return
		}
		_, verr := s.Verify(tampered, now)
		assert.Error(rt, verr, "tampered token must not verify")
	})
}

func TestSigner_Verify_Errors(t *testing.T) {
	t.Parallel()
	s, err := New(testKey(), "v1")
	require.NoError(t, err)
	now := time.Unix(1_700_000_000, 0).UTC()
	good, _, err := s.Mint("host-a", 7, time.Hour, now)
	require.NoError(t, err)

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, err := s.Verify("", now)
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("no dots", func(t *testing.T) {
		t.Parallel()
		_, err := s.Verify("notatoken", now)
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("two segments only", func(t *testing.T) {
		t.Parallel()
		_, err := s.Verify("v1.abc", now)
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("wrong version", func(t *testing.T) {
		t.Parallel()
		_, err := s.Verify("v2"+good[2:], now)
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("bad base64 mac", func(t *testing.T) {
		t.Parallel()
		_, err := s.Verify("v1.YWJj.@@@", now)
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("bad signature", func(t *testing.T) {
		t.Parallel()
		tampered := good[:len(good)-1] + string(flipBase64Char(good[len(good)-1]))
		_, err := s.Verify(tampered, now)
		assert.ErrorIs(t, err, ErrBadSignature)
	})
	t.Run("wrong key id", func(t *testing.T) {
		t.Parallel()
		// Same key material, different serving id: the MAC still matches, so this exercises the kid check specifically.
		other, err := New(testKey(), "v2")
		require.NoError(t, err)
		_, verr := other.Verify(good, now)
		assert.ErrorIs(t, verr, ErrWrongKey)
	})
	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		_, err := s.Verify(good, now.Add(2*time.Hour))
		assert.ErrorIs(t, err, ErrExpired)
	})
}

func TestSigner_Mint_Validation(t *testing.T) {
	t.Parallel()
	s, err := New(testKey(), "v1")
	require.NoError(t, err)
	now := time.Unix(1_700_000_000, 0).UTC()

	_, _, err = s.Mint("", 0, time.Hour, now)
	require.Error(t, err, "empty hostID rejected")
	_, _, err = s.Mint("host-a", 0, 0, now)
	require.Error(t, err, "non-positive ttl rejected")
}
