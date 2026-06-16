// This file holds the cryptographic primitives that back agent host-token authentication: token generation, keyed HMAC-SHA256
// hashing, constant-time verification, and the SHA-256 token-id lookup key. See doc.go for the package contract.

package mysql

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// tokenLen is the size of the random bearer token we issue on successful enroll. 32 bytes
	// → 43 base64url characters, ample for an HMAC-equivalent entropy budget.
	tokenLen int = 32
)

// generateToken returns a fresh random bearer token, base64url (no padding), 43 chars.
func generateToken() (string, error) {
	buf := make([]byte, tokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// tokenID returns the SHA-256 of `token`. This is stored alongside the HMAC hash as a deterministic lookup key so Verify can fetch a
// single candidate row by indexed equality rather than scan every active enrollment. SHA-256 of a 32-byte random token has the same
// entropy as the token and is one-way, so leaking the column does not let an attacker recover the token; the keyed HMAC hash is still
// the authenticator.
func tokenID(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// hashToken returns the authenticator for a bearer token: HMAC-SHA256(pepper, token). The raw token is never stored. The token is a
// 32-byte random secret, not a human-chosen password, so a high-entropy keyed hash gives the same practical resistance to offline
// recovery as a memory-hard KDF while keeping verification sub-microsecond on the authenticated agent hot path. The pepper is a
// server-held secret derived from the deployment root key (see internal/keyring): a read-only database leak yields neither the token
// (the stored value is one-way) nor the ability to forge one (the attacker lacks the pepper).
func hashToken(pepper []byte, token string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(token))
	return mac.Sum(nil)
}

// verifyToken reports whether `token` hashes to `want` under `pepper`. Uses hmac.Equal (a constant-time compare) so the hash-compare
// step does not leak timing information.
func verifyToken(pepper []byte, token string, want []byte) bool {
	if len(want) == 0 {
		return false
	}
	return hmac.Equal(hashToken(pepper, token), want)
}

// ErrTokenMismatch is returned when a presented token does not match any enrolled host.
var ErrTokenMismatch = errors.New("enrollment: token mismatch")

// ErrRotateRaced is returned when RotateHostToken's optimistic-lock UPDATE matched zero rows: another rotation for the same host has
// already swapped the token between the caller's verify and the rotate. Callers map this to a no-op (the other path's rotation already
// produced a fresh token; nothing for this caller to do).
var ErrRotateRaced = errors.New("enrollment: rotate raced with another rotation")
