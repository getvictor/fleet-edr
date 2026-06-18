package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
)

func TestEncodeToken_RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0xFF, 0xFE, 0xFD},
		[]byte("hello world"),
		// 32 bytes: the actual session-token length.
		{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		},
	}
	for _, raw := range cases {
		s := api.EncodeToken(raw)
		got, err := api.DecodeToken(s)
		require.NoError(t, err)
		assert.Equal(t, raw, got)
	}
}

// TestDecodeToken_AcceptsPaddedURLEncoding ensures DecodeToken accepts the padded form some middleboxes emit, in addition to the
// raw-unpadded form EncodeToken produces.
func TestDecodeToken_AcceptsPaddedURLEncoding(t *testing.T) {
	raw := []byte{0xab, 0xcd, 0xef}
	// Hand-written padded base64url for those three bytes is "q83v" with no
	// padding, but for an odd-length payload (4 bytes) it'd need '='.
	rawWithPad := append([]byte{}, raw...)
	rawWithPad = append(rawWithPad, 0x10)
	encoded := "q83vEA=="
	got, err := api.DecodeToken(encoded)
	require.NoError(t, err)
	assert.Equal(t, rawWithPad, got)
}

func TestDecodeToken_RejectsGarbage(t *testing.T) {
	_, err := api.DecodeToken("not-valid-base64-@#$%")
	require.Error(t, err)
}

func TestUserIDFromContext_RoundTrip(t *testing.T) {
	ctx := api.WithUserID(context.Background(), 42)
	got, ok := api.UserIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, int64(42), got)
}

func TestUserIDFromContext_Empty(t *testing.T) {
	got, ok := api.UserIDFromContext(context.Background())
	assert.False(t, ok)
	assert.Zero(t, got)
}

func TestUserIDFromContext_ZeroUserIDNotAuthenticated(t *testing.T) {
	// Pinning user_id 0 should not be reported as authenticated. Guards against a writer accidentally passing a zero-valued int into
	// WithUserID and silently authenticating a request with no user.
	ctx := api.WithUserID(context.Background(), 0)
	got, ok := api.UserIDFromContext(ctx)
	assert.False(t, ok)
	assert.Zero(t, got)
}

func TestSessionFromContext_RoundTrip(t *testing.T) {
	sess := &api.Session{
		UserID:    7,
		ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: []byte("csrf-token-bytes"),
	}
	ctx := api.WithSession(context.Background(), sess)
	got, ok := api.SessionFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, sess, got)
}

func TestSessionFromContext_Empty(t *testing.T) {
	got, ok := api.SessionFromContext(context.Background())
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestForTestAliases_DelegateToWithUserID(t *testing.T) {
	// WithUserIDForTest + WithSessionForTest are backward-compat aliases;
	// assert they delegate to the canonical setters.
	uctx := api.WithUserIDForTest(context.Background(), 11)
	got, ok := api.UserIDFromContext(uctx)
	require.True(t, ok)
	assert.Equal(t, int64(11), got)

	sess := &api.Session{UserID: 11}
	sctx := api.WithSessionForTest(context.Background(), sess)
	gotS, ok := api.SessionFromContext(sctx)
	require.True(t, ok)
	assert.Same(t, sess, gotS)
}
