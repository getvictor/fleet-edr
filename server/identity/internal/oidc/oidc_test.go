package oidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/oidc"
)

// GenerateFlowSecrets returns four distinct, non-empty, URL-safe strings. The PKCE challenge equals base64url(sha256(verifier)) per
// RFC 7636. Catches a regression that would emit deterministic secrets (e.g. a test fixture leaking into production via a build flag).
func TestGenerateFlowSecrets(t *testing.T) {
	t.Parallel()
	state, nonce, verifier, challenge, err := oidc.GenerateFlowSecrets()
	require.NoError(t, err)
	assert.NotEmpty(t, state)
	assert.NotEmpty(t, nonce)
	assert.NotEmpty(t, verifier)
	assert.NotEmpty(t, challenge)
	// All four are different (random).
	assert.NotEqual(t, state, nonce)
	assert.NotEqual(t, state, verifier)
	assert.NotEqual(t, nonce, verifier)
	// PKCE challenge = base64url(sha256(verifier)).
	h := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(h[:])
	assert.Equal(t, want, challenge,
		"code_challenge must be S256 of verifier per RFC 7636 §4.2")
}

// Two consecutive calls produce different secrets: every flow has its own entropy. A repeat would be a critical security bug
// (replayable state + nonce).
func TestGenerateFlowSecrets_Unique(t *testing.T) {
	t.Parallel()
	s1, n1, v1, _, err := oidc.GenerateFlowSecrets()
	require.NoError(t, err)
	s2, n2, v2, _, err := oidc.GenerateFlowSecrets()
	require.NoError(t, err)
	assert.NotEqual(t, s1, s2)
	assert.NotEqual(t, n1, n2)
	assert.NotEqual(t, v1, v2)
}
