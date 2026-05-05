package breakglass

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ChallengeStateCookieName is the cookie that carries the
// signed-and-serialized webauthn.SessionData between a GET
// /admin/break-glass[/setup] (challenge issued) and the matching
// POST (challenge verified). Distinct from the OIDC state cookie so
// the two flows never collide on the same Path scope.
const ChallengeStateCookieName = "edr_breakglass_challenge"

// ErrChallengeStateInvalid is returned by DecodeChallengeState when
// the cookie is missing, malformed, or fails the HMAC check.
// Distinct from the WebAuthn-finish errors so the handler can
// distinguish "browser tampered with the cookie" from "browser
// supplied a bad assertion".
var ErrChallengeStateInvalid = errors.New("breakglass: challenge state invalid")

// EncodeChallengeState serializes a SessionData via gob, prefixes
// an HMAC-SHA256 over the serialized bytes, and base64url-encodes
// the whole thing. The signing key is the same SessionSigningKey
// the OIDC state cookie uses (per spec, single signing key
// rotates the entire pre-auth surface).
//
// gob is deliberate: the SessionData has unexported-by-default
// fields and a future bump of the go-webauthn library may add
// fields. JSON would silently drop unknown fields; gob preserves
// the structural mapping so a re-decode after a library bump
// still recovers the right SessionData.
func EncodeChallengeState(signingKey []byte, sd webauthn.SessionData) (string, error) {
	if len(signingKey) == 0 {
		return "", errors.New("breakglass: signing key is required")
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(sd); err != nil {
		return "", fmt.Errorf("breakglass: gob encode: %w", err)
	}
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(buf.Bytes())
	sig := mac.Sum(nil)
	// Wire layout: base64url(sig).base64url(payload). Same shape as
	// the OIDC state cookie so cookie-handling middleware can split
	// on the dot without per-cookie special cases.
	return base64.RawURLEncoding.EncodeToString(sig) +
		"." +
		base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeChallengeState reverses EncodeChallengeState: split on the
// dot, base64url-decode, verify the HMAC in constant time, gob-
// decode the payload back into a SessionData. Any failure collapses
// to ErrChallengeStateInvalid so the handler can map it to a single
// generic 400 without leaking which sub-step failed.
func DecodeChallengeState(signingKey []byte, raw string) (webauthn.SessionData, error) {
	if len(signingKey) == 0 {
		return webauthn.SessionData{}, errors.New("breakglass: signing key is required")
	}
	parts := bytes.SplitN([]byte(raw), []byte("."), 2)
	if len(parts) != 2 {
		return webauthn.SessionData{}, fmt.Errorf("%w: malformed", ErrChallengeStateInvalid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return webauthn.SessionData{}, fmt.Errorf("signature decode: %w (%w)", ErrChallengeStateInvalid, err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return webauthn.SessionData{}, fmt.Errorf("payload decode: %w: %w", ErrChallengeStateInvalid, err)
	}
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(payload)
	want := mac.Sum(nil)
	if !hmac.Equal(sig, want) {
		return webauthn.SessionData{}, fmt.Errorf("%w: signature mismatch", ErrChallengeStateInvalid)
	}
	var sd webauthn.SessionData
	if err := gob.NewDecoder(bytes.NewReader(payload)).Decode(&sd); err != nil {
		return webauthn.SessionData{}, fmt.Errorf("gob decode: %w: %w", ErrChallengeStateInvalid, err)
	}
	return sd, nil
}
