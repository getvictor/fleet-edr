package mysql

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// testPepper returns a fresh random 32-byte HMAC pepper for the white-box helpers.
func testPepper(t *testing.T) []byte {
	t.Helper()
	p := make([]byte, 32)
	_, err := rand.Read(p)
	require.NoError(t, err)
	return p
}

// TestHashRoundTrip is a white-box test for the package-private token helpers (generateToken / hashToken / verifyToken). The DB-using
// tests are in store_test.go (package mysql_test) to avoid the testdb -> endpoint/bootstrap -> endpoint/internal/mysql cycle.
func TestHashRoundTrip(t *testing.T) {
	t.Parallel()
	pepper := testPepper(t)

	tok, err := generateToken()
	require.NoError(t, err)
	require.Len(t, tok, 43)

	hash := hashToken(pepper, tok)
	require.Len(t, hash, 32) // HMAC-SHA256 output width

	// spec:agent-enrollment/host-tokens-are-stored-and-verified-with-a-fast-keyed-hash/verification-on-the-authenticated-hot-path
	assert.True(t, verifyToken(pepper, tok, hash), "the token that produced the hash must verify")
	// spec:agent-enrollment/host-tokens-are-stored-and-verified-with-a-fast-keyed-hash/a-token-that-does-not-match-is-rejected
	assert.False(t, verifyToken(pepper, "not-the-right-token-not-the-right-token-xxx", hash), "a different token must not verify")
	assert.False(t, verifyToken(pepper, tok, nil), "an empty stored hash must not verify")
	assert.False(t, verifyToken(testPepper(t), tok, hash), "a token hashed under a different pepper must not verify")
}

// TestVerifyTokenProperty pins the HMAC verifier's invariants over a wide input space: the hash a (pepper, token) pair produces always
// verifies under that same pair, and neither a different token nor a different pepper verifies it (collisions are negligible).
func TestVerifyTokenProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		pepper := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "pepper")
		token := rapid.String().Draw(rt, "token")

		hash := hashToken(pepper, token)
		assert.True(rt, verifyToken(pepper, token, hash), "verify must accept the token it hashed")

		if other := rapid.String().Draw(rt, "other"); other != token {
			assert.False(rt, verifyToken(pepper, other, hash), "a different token must not verify")
		}
		otherPepper := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "otherPepper")
		if string(otherPepper) != string(pepper) {
			assert.False(rt, verifyToken(otherPepper, token, hash), "a different pepper must not verify")
		}
	})
}
