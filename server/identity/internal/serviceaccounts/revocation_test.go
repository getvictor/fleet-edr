package serviceaccounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct {
	entries []Entry
	err     error
	calls   int
}

func (f *fakeSource) RevocationEntries(context.Context) ([]Entry, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

func TestSnapshot_Allowed(t *testing.T) {
	t.Parallel()
	src := &fakeSource{entries: []Entry{
		{ClientID: "sa_revoked", Epoch: 2, Revoked: true},
		{ClientID: "sa_rotated", Epoch: 3, Revoked: false},
	}}
	snap := NewSnapshot(src, nil)
	require.NoError(t, snap.Refresh(context.Background()))

	cases := []struct {
		name       string
		clientID   string
		tokenEpoch int64
		want       bool
	}{
		{"absent account allowed", "sa_unknown", 0, true},
		{"revoked never allowed", "sa_revoked", 99, false},
		{"rotated current epoch allowed", "sa_rotated", 3, true},
		{"rotated newer epoch allowed", "sa_rotated", 4, true},
		{"rotated stale epoch rejected", "sa_rotated", 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, snap.Allowed(tc.clientID, tc.tokenEpoch))
		})
	}
	assert.Equal(t, 2, snap.Size())
}

func TestSnapshot_RefreshErrorRetainsPrevious(t *testing.T) {
	t.Parallel()
	src := &fakeSource{entries: []Entry{{ClientID: "sa_revoked", Epoch: 1, Revoked: true}}}
	snap := NewSnapshot(src, nil)
	require.NoError(t, snap.Refresh(context.Background()))
	require.False(t, snap.Allowed("sa_revoked", 5))

	// A failing refresh must NOT drop the snapshot to empty (which would un-revoke the account).
	src.err = errors.New("db down")
	require.Error(t, snap.Refresh(context.Background()))
	assert.False(t, snap.Allowed("sa_revoked", 5), "previous snapshot must be retained on refresh error")
}

func TestSnapshot_emptyAllowsEverything(t *testing.T) {
	t.Parallel()
	snap := NewSnapshot(&fakeSource{}, nil)
	// Before any refresh, a cold snapshot allows everything (fail-open until the first load).
	assert.True(t, snap.Allowed("sa_any", 0))
}

func TestCredentialGeneration(t *testing.T) {
	t.Parallel()
	clientID, err := generateClientID()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(clientID, clientIDPrefix), "client id carries its prefix")

	secret, err := generateSecret()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(secret, secretPrefix), "secret carries its scanning prefix")

	// Distinct calls produce distinct values.
	clientID2, err := generateClientID()
	require.NoError(t, err)
	assert.NotEqual(t, clientID, clientID2)
}

func TestSecretMatches(t *testing.T) {
	t.Parallel()
	secret, err := generateSecret()
	require.NoError(t, err)
	stored := hashSecret(secret)
	assert.True(t, SecretMatches(stored, secret), "the issued secret matches its stored hash")
	assert.False(t, SecretMatches(stored, secret+"x"), "a different secret does not match")
	assert.False(t, SecretMatches(stored, ""), "empty does not match")
}
