// Package signedtoken mints and verifies self-validating host bearer tokens for agent authentication.
//
// A token carries its own identity and validity window, signed with a server-held HMAC-SHA256 key, so the verify path is a local
// signature check with no database lookup. This is the agent hot path: every event upload and command poll presents a token, and at
// fleet scale a per-request DB lookup is the dominant auth cost. Revocation is layered on top by the caller via the token_epoch the
// claims carry (see the endpoint service + revocation snapshot): the signer only proves authenticity + freshness, never "still
// allowed".
//
// Format (single line, ASCII): "v1.<payload>.<mac>" where
//   - "v1" is the format version, folded into the MAC input so a verifier built for v1 cannot be tricked into trusting a re-labelled
//     payload from another format;
//   - <payload> is base64url (no padding) of the JSON Claims;
//   - <mac> is base64url (no padding) of HMAC-SHA256(key, "v1." + <payload>).
//
// The payload is signed, not encrypted: host_id and timestamps are not secret, and a readable token is far easier to debug in QA and
// SigNoz than an opaque blob. The MAC is the only authenticator.
package signedtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// formatVersion is the literal first segment of every token. It is part of the MAC input, so a verifier built for v1 rejects any
// other version at the signature step rather than trusting a re-labelled payload.
const formatVersion = "v1"

// minKeyLen is the floor for the signing key, matching the HMAC-SHA256 output width and the keyring's derived-key length. A shorter
// key would make the MAC effectively unkeyed.
const minKeyLen = 32

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
	key []byte
	kid string
}

// New returns a Signer over key, labelled kid. Returns an error when key is shorter than minKeyLen or kid is empty: both are wiring
// bugs, surfaced loudly rather than producing tokens nobody can verify. The key is cloned so a later mutation of the caller's slice
// cannot change the signer's key material out from under in-flight verifications.
func New(key []byte, kid string) (*Signer, error) {
	if len(key) < minKeyLen {
		return nil, fmt.Errorf("signedtoken: key must be at least %d bytes, got %d", minKeyLen, len(key))
	}
	if kid == "" {
		return nil, errors.New("signedtoken: kid is required")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k, kid: kid}, nil
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
		KeyID:     s.kid,
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signedtoken: marshal claims: %w", err)
	}
	signed := formatVersion + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	token := signed + "." + base64.RawURLEncoding.EncodeToString(s.mac(signed))
	return token, exp.UTC().Truncate(time.Second), nil
}

// Verify checks the token's version, signature, key id, and expiry against now, returning the authenticated claims. It does NOT
// consult any revocation state; the caller layers that on using Claims.Epoch against the revocation snapshot.
func (s *Signer) Verify(token string, now time.Time) (Claims, error) {
	version, payload, mac, ok := split(token)
	if !ok || version != formatVersion {
		return Claims{}, ErrMalformed
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	// Constant-time compare; recompute over the exact received bytes (version + "." + payload), never a re-encoding, so a payload that
	// round-trips differently through json cannot change the verified material.
	if !hmac.Equal(gotMAC, s.mac(version+"."+payload)) {
		return Claims{}, ErrBadSignature
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return Claims{}, ErrMalformed
	}
	// kid lives inside the MAC-protected payload, so a mismatch here is not tampering (the MAC already caught that): it means the token
	// was minted under a key id this Signer doesn't serve. Reject so a retired key's tokens stop verifying once the serving id changes.
	if claims.KeyID != s.kid {
		return Claims{}, ErrWrongKey
	}
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return Claims{}, ErrExpired
	}
	return claims, nil
}

func (s *Signer) mac(signed string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(signed))
	return m.Sum(nil)
}

// split breaks "v1.<payload>.<mac>" into its three segments. Returns ok=false for any shape that is not exactly three non-empty
// dot-separated segments (a fourth dot anywhere, an empty segment, or fewer than two dots).
func split(token string) (version, payload, mac string, ok bool) {
	first := strings.IndexByte(token, '.')
	if first <= 0 {
		return "", "", "", false
	}
	rest := token[first+1:]
	second := strings.IndexByte(rest, '.')
	if second <= 0 {
		return "", "", "", false
	}
	version = token[:first]
	payload = rest[:second]
	mac = rest[second+1:]
	if payload == "" || mac == "" || strings.IndexByte(mac, '.') >= 0 {
		return "", "", "", false
	}
	return version, payload, mac, true
}
