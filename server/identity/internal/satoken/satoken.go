// Package satoken mints and verifies self-validating service-account access tokens (issue #376, ADR-0013).
//
// A token is exchanged for at the client-credentials token endpoint and then presented as a bearer credential on the API. It carries
// its own identity, role, and validity window, signed with a server-held HMAC-SHA256 key, so the verify path on the API hot path is a
// local signature check with no database lookup, the same shape as the host-token machinery in server/endpoint/internal/signedtoken.
// Bounded-context rules (ADR-0004) forbid the identity context importing that endpoint-internal package, so the format is mirrored
// here rather than shared.
//
// Format (single line, ASCII): "v1.<payload>.<mac>" where <payload> is base64url(no pad) of the JSON Claims and <mac> is
// base64url(no pad) of HMAC-SHA256(key, "v1." + <payload>). The version literal is folded into the MAC input so a verifier built for
// v1 cannot be tricked into trusting a re-labelled payload. The payload is signed, not encrypted: subject and timestamps are not
// secret, and a readable token is far easier to debug. Revocation is layered on top by the caller via the epoch the claims carry (see
// the revocation snapshot); the signer only proves authenticity, audience, and freshness, never "still allowed".
package satoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const formatVersion = "v1"

// minKeyLen is the floor for the signing key, matching the HMAC-SHA256 output width and the keyring's derived-key length.
const minKeyLen = 32

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
	key      []byte
	kid      string
	audience string
}

// New returns a Signer over key, labelled kid, binding tokens to audience. Returns an error when key is shorter than minKeyLen or kid
// or audience is empty: all are wiring bugs, surfaced loudly. The key is cloned so a later mutation of the caller's slice cannot change
// the signer's key material out from under in-flight verifications.
func New(key []byte, kid, audience string) (*Signer, error) {
	if len(key) < minKeyLen {
		return nil, fmt.Errorf("satoken: key must be at least %d bytes, got %d", minKeyLen, len(key))
	}
	if kid == "" {
		return nil, errors.New("satoken: kid is required")
	}
	if audience == "" {
		return nil, errors.New("satoken: audience is required")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k, kid: kid, audience: audience}, nil
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
		KeyID:     s.kid,
		TokenID:   jti,
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("satoken: marshal claims: %w", err)
	}
	signed := formatVersion + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	token := signed + "." + base64.RawURLEncoding.EncodeToString(s.mac(signed))
	return token, exp.UTC().Truncate(time.Second), nil
}

// Verify checks the token's version, signature, key id, audience, and expiry against now, returning the authenticated claims. It does
// NOT consult any revocation state; the caller layers that on using Claims.Epoch against the revocation snapshot.
func (s *Signer) Verify(token string, now time.Time) (Claims, error) {
	version, payload, mac, ok := split(token)
	if !ok || version != formatVersion {
		return Claims{}, ErrMalformed
	}
	// Strict() rejects a non-canonical encoding (non-zero trailing bits in the final base64 char), without which the MAC is malleable.
	gotMAC, err := base64.RawURLEncoding.Strict().DecodeString(mac)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	// hmac.Equal is only constant-time over equal-length inputs; reject a structurally-wrong MAC length before the compare.
	if len(gotMAC) != sha256.Size {
		return Claims{}, ErrMalformed
	}
	// Constant-time compare over the exact received bytes (version + "." + payload), never a re-encoding.
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
	if claims.KeyID != s.kid {
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

func (s *Signer) mac(signed string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(signed))
	return m.Sum(nil)
}

// randomID returns a 128-bit random hex token id from crypto/rand.
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// split breaks "v1.<payload>.<mac>" into its three segments. Returns ok=false for any shape that is not exactly three non-empty
// dot-separated segments.
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
