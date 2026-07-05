// Package satoken mints and verifies self-validating service-account access tokens (issue #376, ADR-0013).
//
// A token is exchanged for at the client-credentials token endpoint and then presented as a bearer credential on the API. It carries
// its own identity, role, and validity window, signed with a server-held HMAC-SHA256 key, so the verify path on the API hot path is a
// local signature check with no database lookup, the same shape as the host token in server/endpoint/internal/signedtoken.
//
// The "v1.<payload>.<mac>" envelope (base64url JSON payload, HMAC-SHA256 over the version-prefixed payload) is the shared
// internal/hmactoken primitive, which both token types use so the identity and endpoint contexts share the security-critical core
// without importing each other (ADR-0004). This package owns the service-account Claims shape and the post-verify claim checks (key
// id, audience, expiry). Revocation is layered on top by the caller via the epoch the claims carry (see the revocation snapshot); the
// signer only proves authenticity, audience, and freshness, never "still allowed".
package satoken

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fleetdm/edr/internal/hmactoken"
)

// Claims is the authenticated payload of a service-account access token. JSON tags are short because the token rides on every API
// request the service account makes.
type Claims struct {
	Subject   string `json:"sub"`           // service-account client id
	Audience  string `json:"aud"`           // the API audience this token is minted for
	Role      string `json:"role"`          // the single bound role id, evaluated by the authz chokepoint
	Epoch     int64  `json:"ep"`            // revocation generation; checked against the per-replica snapshot
	Principal string `json:"pid,omitempty"` // the service account's principal id (svc_<id>); carried so the actor survives auth with no DB read
	Label     string `json:"nm,omitempty"`  // the service account's display name, snapshotted onto audit rows without a DB read
	IssuedAt  int64  `json:"iat"`           // unix seconds
	ExpiresAt int64  `json:"exp"`           // unix seconds
	KeyID     string `json:"kid"`
	TokenID   string `json:"jti"` // unique per mint; correlation + forward-compat with a future jti denylist
}

// Verification failures. They collapse to a single opaque "invalid token" at the API boundary so the wire never distinguishes
// "expired" from "forged" from "wrong audience": doing so would be an oracle.
var (
	ErrMalformed     = errors.New("satoken: malformed token")
	ErrBadSignature  = errors.New("satoken: signature mismatch")
	ErrWrongKey      = errors.New("satoken: unknown key id")
	ErrWrongAudience = errors.New("satoken: wrong audience")
	ErrExpired       = errors.New("satoken: token expired")
)

// Signer mints and verifies tokens under one HMAC key identified by kid, for one audience. Construct one per key id.
type Signer struct {
	key      *hmactoken.Key
	audience string
}

// New returns a Signer over key, labelled kid, binding tokens to audience. Returns an error when key is too short or kid or audience
// is empty (all wiring bugs, surfaced loudly); the underlying key is cloned so a later mutation of the caller's slice cannot change the
// signer's key material out from under in-flight verifications.
func New(key []byte, kid, audience string) (*Signer, error) {
	k, err := hmactoken.NewKey(key, kid)
	if err != nil {
		return nil, err
	}
	if audience == "" {
		return nil, errors.New("satoken: audience is required")
	}
	return &Signer{key: k, audience: audience}, nil
}

// MintInput is the per-token data the caller supplies; the Signer fills in audience, timestamps, kid, and a random jti.
type MintInput struct {
	Subject   string
	Role      string
	Epoch     int64
	Principal string // the service account's principal id (svc_<id>)
	Label     string // the service account's display name
}

// Mint returns a token for in, valid for ttl from now, plus the absolute (second-truncated, UTC) expiry. now is injected so callers
// and tests keep one clock.
func (s *Signer) Mint(in MintInput, ttl time.Duration, now time.Time) (string, time.Time, error) {
	if in.Subject == "" {
		return "", time.Time{}, errors.New("satoken: subject is required")
	}
	if in.Role == "" {
		return "", time.Time{}, errors.New("satoken: role is required")
	}
	if ttl <= 0 {
		return "", time.Time{}, errors.New("satoken: ttl must be positive")
	}
	jti, err := randomID()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("satoken: generate jti: %w", err)
	}
	exp := now.Add(ttl)
	claims := Claims{
		Subject:   in.Subject,
		Audience:  s.audience,
		Role:      in.Role,
		Epoch:     in.Epoch,
		Principal: in.Principal,
		Label:     in.Label,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		KeyID:     s.key.KID(),
		TokenID:   jti,
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("satoken: marshal claims: %w", err)
	}
	return s.key.Seal(payloadJSON), exp.UTC().Truncate(time.Second), nil
}

// Verify checks the token's version, signature, key id, audience, and expiry against now, returning the authenticated claims. It does
// NOT consult any revocation state; the caller layers that on using Claims.Epoch against the revocation snapshot.
func (s *Signer) Verify(token string, now time.Time) (Claims, error) {
	payloadJSON, err := s.key.Open(token)
	if err != nil {
		if errors.Is(err, hmactoken.ErrBadSignature) {
			return Claims{}, ErrBadSignature
		}
		return Claims{}, ErrMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return Claims{}, ErrMalformed
	}
	if claims.KeyID != s.key.KID() {
		return Claims{}, ErrWrongKey
	}
	if claims.Audience != s.audience {
		return Claims{}, ErrWrongAudience
	}
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return Claims{}, ErrExpired
	}
	return claims, nil
}

// randomID returns a 128-bit random hex token id from crypto/rand.
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
