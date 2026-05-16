package mysql

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHashRoundTrip is a white-box test for the package-private token helpers (generateToken / hashToken / verifyToken). The DB-using
// tests are in store_test.go (package mysql_test) to avoid the testdb -> endpoint/bootstrap -> endpoint/internal/mysql cycle.
func TestHashRoundTrip(t *testing.T) {
	tok, err := generateToken()
	require.NoError(t, err)
	require.Len(t, tok, 43)

	hash, salt, err := hashToken(tok)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	require.Len(t, salt, argonSaltLen)

	assert.True(t, verifyToken(tok, hash, salt))
	assert.False(t, verifyToken("not-the-right-token-not-the-right-token-xxx", hash, salt))
	assert.False(t, verifyToken(tok, nil, salt))
	assert.False(t, verifyToken(tok, hash, nil))
}
