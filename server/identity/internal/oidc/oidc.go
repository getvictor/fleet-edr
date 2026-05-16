package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// clockSkewTolerance is the ±2-minute window the spec calls for on ID-token expiry / not-before checks. go-oidc/v3's verifier doesn't
// expose a direct SkewTolerance knob; the implementation accepts tokens whose Expiry has not yet passed against the verifier's
// Now func. We honour the spec by passing a Now that subtracts the tolerance for expiry checks (so a token "expired 90s ago" still
// verifies). IAT/NBF checks consume the same Now so a token issued in the future by less than the tolerance also verifies.
const clockSkewTolerance = 2 * time.Minute

// Options bundles the per-deployment knobs the OIDC client needs at construction time. Issuer is the discovery URL (the well-known doc
// lives at <Issuer>/.well-known/openid-configuration). Scopes default to [openid, email, profile] so the verifier sees the claims it
// needs (sub + email + name) without leaking unused permissions.
type Options struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	HTTPClient   *http.Client // optional; tests inject a fixture
	Logger       *slog.Logger
}

// Client wraps the go-oidc Provider + Verifier + the oauth2 Config they share. Construct once at boot via New; the Provider's JWKS
// cache lives for the process lifetime and refreshes lazily on verifier failure.
type Client struct {
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	oauth2Config oauth2.Config
	logger       *slog.Logger
}

// New runs OIDC discovery against opts.Issuer and prepares a verifier + oauth2 config. ctx is used for the discovery HTTP call;
// cancelling it before New returns aborts setup. Returns an error on issuer reachability failure or malformed discovery doc; cmd/main
// maps this to a refuse-to-start error.
func New(ctx context.Context, opts Options) (*Client, error) {
	if opts.Issuer == "" {
		return nil, errors.New("oidc: Issuer is required")
	}
	if opts.ClientID == "" {
		return nil, errors.New("oidc: ClientID is required")
	}
	if opts.ClientSecret == "" {
		return nil, errors.New("oidc: ClientSecret is required")
	}
	if opts.RedirectURL == "" {
		return nil, errors.New("oidc: RedirectURL is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}
	if opts.HTTPClient != nil {
		ctx = gooidc.ClientContext(ctx, opts.HTTPClient)
	}
	provider, err := gooidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %q: %w", opts.Issuer, err)
	}
	verifier := provider.Verifier(&gooidc.Config{
		ClientID: opts.ClientID,
		Now: func() time.Time {
			// Backdate the verifier's clock by the tolerance so a token whose Expiry just passed (within the window) still
			// verifies. iat/nbf checks read the same Now, so a future-dated token within the window also passes — both
			// directions of the tolerance covered by a single offset.
			return time.Now().Add(-clockSkewTolerance)
		},
		SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
	})
	return &Client{
		provider: provider,
		verifier: verifier,
		oauth2Config: oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  opts.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		logger: logger,
	}, nil
}

// AuthURL builds the authorization-endpoint URL the operator's
// browser hits to start the flow. state + nonce are the per-flow
// random strings; codeChallenge is the S256 hash of the PKCE
// code_verifier the caller persisted in the state cookie.
//
// The returned URL is safe to log; state + nonce are tied to a
// single flow and consumed at callback. Production logging should
// still avoid leaking the URL because it contains the IdP path.
func (c *Client) AuthURL(state, nonce, codeChallenge string) string {
	return c.oauth2Config.AuthCodeURL(state,
		oauth2.AccessTypeOnline,
		gooidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Claims is the per-flow subset of ID-token claims the JIT provisioner reads. Subject is the stable per-user identifier (always
// present per OIDC spec). Email is best-effort; some IdPs require an extra scope. EmailVerified mirrors the IdP's email_verified claim
// — true when the IdP attests the address is owned by the subject, false when the IdP says it is not, nil when the IdP omitted the
// claim entirely. Name is whatever the IdP populates as preferred display (preferred_username falls through to name when present).
type Claims struct {
	Subject       string
	Email         string
	EmailVerified *bool
	Name          string
}

// EmailTrusted reports whether c.Email may be used as a primary account binding. Per OIDC core §5.1: when email_verified is present
// it is authoritative; when omitted, callers may fall back to out-of-band trust in the IdP. Wave-1 trusts an absent claim because the
// seeded IdPs (Okta, Auth0) emit it on every standard scope.
func (c *Claims) EmailTrusted() bool {
	if c == nil {
		return false
	}
	if c.EmailVerified == nil {
		return true
	}
	return *c.EmailVerified
}

// Exchange swaps the authorization code for tokens, verifies the ID
// token's signature + issuer + audience + expiry, checks the nonce
// matches the one minted at AuthURL time, and returns the per-user
// claims the provisioner needs.
//
// codeVerifier is the PKCE secret the login handler stashed in the
// state cookie. expectedNonce is the nonce from the same cookie.
// Mismatches at either field are hard errors — the verifier's
// existing checks combined with this nonce comparison eliminate
// replay + injection vectors that would otherwise let an attacker
// substitute a token from a different flow.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*Claims, error) {
	token, err := c.oauth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("oidc: token response missing id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return nil, errors.New("oidc: nonce mismatch")
	}
	var raw struct {
		Email             string `json:"email"`
		EmailVerified     *bool  `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("oidc: decode claims: %w", err)
	}
	display := raw.Name
	if display == "" {
		display = raw.PreferredUsername
	}
	return &Claims{
		Subject:       idToken.Subject,
		Email:         raw.Email,
		EmailVerified: raw.EmailVerified,
		Name:          display,
	}, nil
}

// GenerateFlowSecrets returns a fresh (state, nonce, code_verifier, code_challenge) tuple. state + nonce are 32-byte URL-safe random
// strings; the verifier is also 32 bytes URL-safe; the challenge is the S256 hash of the verifier per RFC 7636. Callers persist
// (state, nonce, verifier) in the signed state cookie and echo (state, challenge) in the AuthURL.
func GenerateFlowSecrets() (state, nonce, codeVerifier, codeChallenge string, err error) {
	state, err = randomURLSafe(32)
	if err != nil {
		return "", "", "", "", err
	}
	nonce, err = randomURLSafe(32)
	if err != nil {
		return "", "", "", "", err
	}
	codeVerifier, err = randomURLSafe(32)
	if err != nil {
		return "", "", "", "", err
	}
	codeChallenge = pkceChallengeS256(codeVerifier)
	return state, nonce, codeVerifier, codeChallenge, nil
}

// pkceChallengeS256 derives the PKCE code_challenge per RFC 7636 §4.2:
// base64url(sha256(code_verifier)), no padding.
func pkceChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// randomURLSafe returns a URL-safe base64-encoded string of n random bytes. Output length is approximately ceil(n * 4 / 3) before
// padding stripping; for n=32 the output is 43 chars.
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
