package oidc

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// spec:server-identity-authentication/okta-oidc-is-the-primary-login-path/operator-initiates-sso-login
//
// Pins the authorize-URL contract the SSO-initiation scenario describes: the redirect the operator's browser follows carries the
// configured client_id, the deployment's redirect_url, the openid/profile/email scope set, the server-generated state, and a PKCE
// code_challenge with method S256. AuthURL reads only the Client's oauth2Config (no IdP discovery), so this in-package test
// constructs a Client with a known config directly and asserts every query parameter the scenario's THEN clause names. The
// handler-level 302 to this URL + the state cookie are pinned by TestHandleLogin_SetsCookieAndRedirects; the S256 derivation of
// the code_challenge from the verifier is pinned by TestGenerateFlowSecrets.
func TestClientAuthURL_CarriesPKCEAndConfiguredParams(t *testing.T) {
	t.Parallel()
	c := &Client{
		oauth2Config: oauth2.Config{
			ClientID:    "edr-client-id",
			RedirectURL: "https://edr.example.com/api/auth/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example.com/authorize"},
			Scopes:      []string{"openid", "profile", "email"},
		},
	}

	raw := c.AuthURL("STATE-XYZ", "NONCE-ABC", "CHALLENGE-123")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "idp.example.com", u.Host)
	assert.Equal(t, "/authorize", u.Path)

	q := u.Query()
	assert.Equal(t, "edr-client-id", q.Get("client_id"))
	assert.Equal(t, "https://edr.example.com/api/auth/callback", q.Get("redirect_uri"))
	assert.Equal(t, "openid profile email", q.Get("scope"))
	assert.Equal(t, "STATE-XYZ", q.Get("state"))
	assert.Equal(t, "CHALLENGE-123", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "code", q.Get("response_type"))
}
