// Package signedtoken mints and verifies self-validating host bearer tokens for agent authentication.
//
// A token carries its own identity and validity window, signed with a server-held HMAC-SHA256 key, so the verify path is a local
// signature check with no database lookup. This is the agent hot path: every event upload and command poll presents a token, and at
// fleet scale a per-request DB lookup is the dominant auth cost. Revocation is layered on top by the caller via the token_epoch the
// claims carry (see the endpoint service + revocation snapshot): the signer only proves authenticity + freshness, never "still
// allowed".
//
// The "v1.<payload>.<mac>" envelope (base64url JSON payload, HMAC-SHA256 over the version-prefixed payload) is the shared
// internal/hmactoken primitive; this package owns the host-token Claims shape and the post-verify claim checks (key id, expiry). The
// service-account token in server/identity/internal/satoken shares that same primitive rather than a copy.
package signedtoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fleetdm/edr/internal/hmactoken"
)

// Claims is the authenticated payload of a host token. JSON tags are short because the token rides on every agent request; HPACK
// compresses the repeated header, but the bytes still travel until the connection's dynamic table warms.
type Claims struct {
	HostID    string `json:"hid"`
	Epoch     int64  `json:"ep"`
	IssuedAt  int64  `json:"iat"` // unix seconds
	ExpiresAt int64  `json:"exp"` // unix seconds
	KeyID     string `json:"kid"`
}

// Verification failures. They all collapse to a single opaque "invalid token" at the API boundary (the endpoint service maps every
// one to api.ErrInvalidToken) so the wire never distinguishes "expired" from "forged": doing so would be an oracle.
var (
	ErrMalformed    = errors.New("signedtoken: malformed token")
	ErrBadSignature = errors.New("signedtoken: signature mismatch")
	ErrWrongKey     = errors.New("signedtoken: unknown key id")
	ErrExpired      = errors.New("signedtoken: token expired")
)

// Signer mints and verifies tokens under one HMAC key identified by kid. The kid is carried in the claims and checked on verify so a
// future key rotation (mint under a new id while still verifying the old during an overlap window) is a constant-time addition rather
// than a wire break. Construct one per key id.
type Signer struct {
	key *hmactoken.Key
}

// New returns a Signer over key, labelled kid. Returns an error when key is too short or kid is empty (both wiring bugs, surfaced
// loudly rather than producing tokens nobody can verify); the underlying key is cloned so a later mutation of the caller's slice
// cannot change the signer's key material out from under in-flight verifications.
func New(key []byte, kid string) (*Signer, error) {
	k, err := hmactoken.NewKey(key, kid)
	if err != nil {
		return nil, err
	}
	return &Signer{key: k}, nil
}

// Mint returns a token for hostID at the given epoch, valid for ttl from now, plus the absolute (second-truncated, UTC) expiry. now is
// injected so callers and tests keep one clock; the issuer's clock is authoritative for exp.
func (s *Signer) Mint(hostID string, epoch int64, ttl time.Duration, now time.Time) (string, time.Time, error) {
	if hostID == "" {
		return "", time.Time{}, errors.New("signedtoken: hostID is required")
	}
	if ttl <= 0 {
		return "", time.Time{}, errors.New("signedtoken: ttl must be positive")
	}
	exp := now.Add(ttl)
	claims := Claims{
		HostID:    hostID,
		Epoch:     epoch,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		KeyID:     s.key.KID(),
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signedtoken: marshal claims: %w", err)
	}
	return s.key.Seal(payloadJSON), exp.UTC().Truncate(time.Second), nil
}

// Verify checks the token's version, signature, key id, and expiry against now, returning the authenticated claims. It does NOT
// consult any revocation state; the caller layers that on using Claims.Epoch against the revocation snapshot.
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
	// kid lives inside the MAC-protected payload, so a mismatch here is not tampering (the MAC already caught that): it means the token
	// was minted under a key id this Signer doesn't serve. Reject so a retired key's tokens stop verifying once the serving id changes.
	if claims.KeyID != s.key.KID() {
		return Claims{}, ErrWrongKey
	}
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return Claims{}, ErrExpired
	}
	return claims, nil
}
