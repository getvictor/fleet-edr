// Package hmactoken implements the shared "v1.<payload>.<mac>" self-validating token envelope: a base64url (no padding) JSON payload
// authenticated by HMAC-SHA256 over the version-prefixed payload. The verify path is a local signature check with no database lookup,
// which is why both token flavours are on request hot paths.
//
// It is the security-critical crypto core behind two context-owned token types that must not import each other (ADR-0004): the host
// bearer token (server/endpoint/internal/signedtoken) and the service-account access token (server/identity/internal/satoken). Each of
// those packages owns its own Claims shape and its own post-verify claim checks (key id, audience, expiry) and delegates only the
// sign/verify envelope here, so the two bounded contexts share the primitive through internal/ rather than sideways.
//
// Format (single line, ASCII): "v1.<payload>.<mac>" where
//   - "v1" is the format version, folded into the MAC input so a verifier built for v1 cannot be tricked into trusting a re-labelled
//     payload from another format;
//   - <payload> is base64url (no padding) of the payload bytes (the caller's JSON claims);
//   - <mac> is base64url (no padding) of HMAC-SHA256(key, "v1." + <payload>).
//
// The payload is signed, not encrypted: it is not secret, and a readable token is far easier to debug in QA and SigNoz than an opaque
// blob. The MAC is the only authenticator. Open performs the envelope + signature checks only; the caller unmarshals the returned
// payload and applies its own claim checks.
package hmactoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// formatVersion is the literal first segment of every token. It is part of the MAC input, so a verifier built for v1 rejects any
// other version at the signature step rather than trusting a re-labelled payload.
const formatVersion = "v1"

// minKeyLen is the floor for the signing key, matching the HMAC-SHA256 output width and the keyring's derived-key length. A shorter
// key would make the MAC effectively unkeyed.
const minKeyLen = 32

// Envelope-level failures. A caller collapses these (and its own claim-check failures) to a single opaque "invalid token" at the API
// boundary so the wire never distinguishes "malformed" from "forged": doing so would be an oracle.
var (
	ErrMalformed    = errors.New("hmactoken: malformed token")
	ErrBadSignature = errors.New("hmactoken: signature mismatch")
)

// Key seals and opens tokens under one HMAC key identified by kid. The kid is carried by the caller inside the (MAC-protected)
// payload and checked by the caller on open, so a future key rotation is a constant-time addition rather than a wire break. Construct
// one per key id with NewKey.
type Key struct {
	key []byte
	kid string
}

// NewKey returns a Key over key, labelled kid. Returns an error when key is shorter than minKeyLen or kid is empty: both are wiring
// bugs, surfaced loudly rather than producing tokens nobody can verify. The key is cloned so a later mutation of the caller's slice
// cannot change the key material out from under in-flight verifications.
func NewKey(key []byte, kid string) (*Key, error) {
	if len(key) < minKeyLen {
		return nil, fmt.Errorf("hmactoken: key must be at least %d bytes, got %d", minKeyLen, len(key))
	}
	if kid == "" {
		return nil, errors.New("hmactoken: kid is required")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Key{key: k, kid: kid}, nil
}

// KID returns the key id this Key seals and opens under. Callers stamp it into their claims at mint time and compare it on open.
func (k *Key) KID() string { return k.kid }

// Seal encodes payload into "v1.<payload>.<mac>": base64url(no pad) of payload, authenticated by HMAC-SHA256 over the
// version-prefixed encoded payload.
func (k *Key) Seal(payload []byte) string {
	signed := formatVersion + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signed + "." + base64.RawURLEncoding.EncodeToString(k.mac(signed))
}

// Open verifies the version and MAC of token and returns the authenticated payload bytes. It performs only the envelope + signature
// checks; the caller unmarshals the payload and applies its own claim checks (key id, audience, expiry). It returns ErrBadSignature
// for a valid-shape token whose MAC does not match, and ErrMalformed for any structurally-invalid token.
func (k *Key) Open(token string) ([]byte, error) {
	version, payload, mac, ok := split(token)
	if !ok || version != formatVersion {
		return nil, ErrMalformed
	}
	// Strict() rejects a non-canonical encoding (non-zero trailing bits in the final base64 char). Without it the MAC is malleable: the
	// last char carries 2 unused bits, so a token whose final byte is altered only in those bits decodes to the same 32 MAC bytes and
	// still verifies. Strict decoding makes every byte of the token significant.
	gotMAC, err := base64.RawURLEncoding.Strict().DecodeString(mac)
	if err != nil {
		return nil, ErrMalformed
	}
	// hmac.Equal is only constant-time over equal-length inputs; a MAC that does not decode to the HMAC-SHA256 width is structurally
	// malformed, not a signature mismatch. Reject it here so the constant-time compare below only ever sees two 32-byte slices.
	if len(gotMAC) != sha256.Size {
		return nil, ErrMalformed
	}
	// Constant-time compare; recompute over the exact received bytes (version + "." + payload), never a re-encoding, so a payload that
	// round-trips differently through json cannot change the verified material.
	if !hmac.Equal(gotMAC, k.mac(version+"."+payload)) {
		return nil, ErrBadSignature
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, ErrMalformed
	}
	return payloadBytes, nil
}

func (k *Key) mac(signed string) []byte {
	m := hmac.New(sha256.New, k.key)
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
