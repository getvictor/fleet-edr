package oidc_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/oidc"
)

// fakeProvider is an OIDC provider on httptest: discovery, a JWKS with one RSA key, and a token endpoint that returns an ID token signed
// with that key carrying idClaims.
func fakeProvider(t *testing.T, idClaims func(issuer string) map[string]any) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(v))
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth", "token_endpoint": srv.URL + "/token",
			"jwks_uri": srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
		assert.NoError(t, err)
		payload, err := json.Marshal(idClaims(srv.URL))
		assert.NoError(t, err)
		signingInput := b64(header) + "." + b64(payload)
		digest := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		assert.NoError(t, err)
		writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": signingInput + "." + b64(sig)})
	})
	return srv
}

// The exchange hands the provisioner every claim of the verified ID token, so a groups claim named only at runtime reaches the mapping.
func TestClient_ExchangeCarriesEveryClaim(t *testing.T) {
	t.Parallel()
	srv := fakeProvider(t, func(issuer string) map[string]any {
		now := time.Now()
		return map[string]any{
			"iss": issuer, "sub": "subject-1", "aud": "edr", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": "nonce-1",
			"email": "alice@example.com", "email_verified": true, "name": "Alice",
			"groups": []string{"edr-admins", "engineering"}, "department": "security",
		}
	})
	client, err := oidc.New(t.Context(), oidc.Options{
		Issuer: srv.URL, ClientID: "edr", ClientSecret: "secret", RedirectURL: "https://edr.example.com/api/auth/callback",
	})
	require.NoError(t, err)

	claims, err := client.Exchange(t.Context(), "code", "verifier", "nonce-1")
	require.NoError(t, err)
	assert.Equal(t, "subject-1", claims.Subject)
	assert.Equal(t, "alice@example.com", claims.Email)
	assert.Equal(t, []string{"edr-admins", "engineering"}, claims.Groups("groups"))
	assert.Equal(t, "security", claims.Raw["department"])
}
