package satoken_test

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/identity/internal/satoken"
)

func newSigner(t *testing.T) *satoken.Signer {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	s, err := satoken.New(key, "v1", "edr-api")
	require.NoError(t, err)
	return s
}

func TestNew_rejectsBadInputs(t *testing.T) {
	t.Parallel()
	good := make([]byte, 32)
	cases := []struct {
		name     string
		key      []byte
		kid      string
		audience string
	}{
		{"short key", make([]byte, 31), "v1", "edr-api"},
		{"empty kid", good, "", "edr-api"},
		{"empty audience", good, "v1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := satoken.New(tc.key, tc.kid, tc.audience)
			require.Error(t, err)
		})
	}
}

// TestMintVerify_roundTrip is the core invariant: any valid claims input round-trips through Mint then Verify unchanged.
func TestMintVerify_roundTrip(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	now := time.Unix(1_700_000_000, 0)
	rapid.Check(t, func(rt *rapid.T) {
		subject := rapid.StringMatching(`[a-zA-Z0-9_-]{1,64}`).Draw(rt, "subject")
		role := rapid.SampledFrom([]string{"analyst", "senior_analyst", "auditor"}).Draw(rt, "role")
		epoch := rapid.Int64Range(0, 1<<40).Draw(rt, "epoch")
		ttlSecs := rapid.Int64Range(1, 86_400).Draw(rt, "ttl")
		ttl := time.Duration(ttlSecs) * time.Second

		token, exp, err := signer.Mint(satoken.MintInput{Subject: subject, Role: role, Epoch: epoch}, ttl, now)
		require.NoError(rt, err)
		require.Equal(rt, now.Add(ttl).UTC().Truncate(time.Second), exp)

		claims, err := signer.Verify(token, now)
		require.NoError(rt, err)
		assert.Equal(rt, subject, claims.Subject)
		assert.Equal(rt, role, claims.Role)
		assert.Equal(rt, epoch, claims.Epoch)
		assert.Equal(rt, "edr-api", claims.Audience)
		assert.Equal(rt, "v1", claims.KeyID)
		assert.NotEmpty(rt, claims.TokenID)
		assert.Equal(rt, now.Unix(), claims.IssuedAt)
	})
}

func TestMint_uniqueTokenID(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	now := time.Unix(1_700_000_000, 0)
	in := satoken.MintInput{Subject: "sa-abc", Role: "analyst", Epoch: 0}
	tok1, _, err := signer.Mint(in, time.Minute, now)
	require.NoError(t, err)
	tok2, _, err := signer.Mint(in, time.Minute, now)
	require.NoError(t, err)
	c1, err := signer.Verify(tok1, now)
	require.NoError(t, err)
	c2, err := signer.Verify(tok2, now)
	require.NoError(t, err)
	assert.NotEqual(t, c1.TokenID, c2.TokenID, "each mint must carry a fresh jti")
}

func TestMint_rejectsBadInputs(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name string
		in   satoken.MintInput
		ttl  time.Duration
	}{
		{"empty subject", satoken.MintInput{Subject: "", Role: "analyst"}, time.Minute},
		{"empty role", satoken.MintInput{Subject: "sa", Role: ""}, time.Minute},
		{"non-positive ttl", satoken.MintInput{Subject: "sa", Role: "analyst"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := signer.Mint(tc.in, tc.ttl, now)
			require.Error(t, err)
		})
	}
}

func TestVerify_expired(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	now := time.Unix(1_700_000_000, 0)
	token, _, err := signer.Mint(satoken.MintInput{Subject: "sa", Role: "analyst"}, time.Minute, now)
	require.NoError(t, err)
	_, err = signer.Verify(token, now.Add(time.Minute)) // exp is exclusive: at exp it is expired
	require.ErrorIs(t, err, satoken.ErrExpired)
	_, err = signer.Verify(token, now.Add(2*time.Minute))
	require.ErrorIs(t, err, satoken.ErrExpired)
}

func TestVerify_tamperedSignature(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	now := time.Unix(1_700_000_000, 0)
	token, _, err := signer.Mint(satoken.MintInput{Subject: "sa", Role: "analyst"}, time.Minute, now)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	// Flip the last character of the payload; the recomputed MAC will not match.
	payload := []byte(parts[1])
	if payload[len(payload)-1] == 'A' {
		payload[len(payload)-1] = 'B'
	} else {
		payload[len(payload)-1] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]
	_, err = signer.Verify(tampered, now)
	require.Error(t, err)
}

func TestVerify_wrongKey(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	signerA := newSigner(t)
	token, _, err := signerA.Mint(satoken.MintInput{Subject: "sa", Role: "analyst"}, time.Minute, now)
	require.NoError(t, err)
	// A signer with a different key (and thus different MAC) rejects at the signature step.
	signerB := newSigner(t)
	_, err = signerB.Verify(token, now)
	require.ErrorIs(t, err, satoken.ErrBadSignature)
}

func TestVerify_wrongAudience(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	// Same key + kid, different audience: signature passes, audience check rejects.
	minter, err := satoken.New(key, "v1", "edr-api")
	require.NoError(t, err)
	verifier, err := satoken.New(key, "v1", "other-deployment")
	require.NoError(t, err)
	token, _, err := minter.Mint(satoken.MintInput{Subject: "sa", Role: "analyst"}, time.Minute, now)
	require.NoError(t, err)
	_, err = verifier.Verify(token, now)
	require.ErrorIs(t, err, satoken.ErrWrongAudience)
}

func TestVerify_malformed(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	now := time.Unix(1_700_000_000, 0)
	cases := []string{
		"",
		"v1",
		"v1.onlytwo",
		"v2.abc.def",         // wrong version
		"v1..def",            // empty payload
		"v1.abc.",            // empty mac
		"v1.abc.def.ghi",     // extra segment
		"v1.not_base64!.bad", // payload junk handled downstream; mac decode fails first
	}
	for _, tok := range cases {
		_, err := signer.Verify(tok, now)
		require.Error(t, err, "token %q must not verify", tok)
	}
}
