// Package enrollment owns per-host enrollment: token generation, argon2id hashing, and the
// CRUD that backs the `enrollments` table. The wire handler lives in handler.go; this file
// focuses on the cryptographic and storage primitives.
package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters chosen per OWASP Password Storage Cheat Sheet 2024 for a modern server
// running interactive hashing. ~30 ms per hash on an M-series Mac. Every other request on the
// hot path is a constant-time compare against the stored hash, not a fresh hash, so steady-
// state auth is microseconds.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16

	// tokenLen is the size of the random bearer token we issue on successful enroll. 32 bytes
	// → 43 base64url characters, ample for an HMAC-equivalent entropy budget.
	tokenLen = 32
)

// generateToken returns a fresh random bearer token, base64url (no padding), 43 chars.
func generateToken() (string, error) {
	buf := make([]byte, tokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// tokenID returns the SHA-256 of `token`. This is stored alongside the argon2id hash/salt as
// a deterministic lookup key so Verify can fetch a single candidate row by indexed equality
// rather than scan every active enrollment. SHA-256 of a 32-byte random token has the same
// entropy as the token and is one-way, so leaking the column does not let an attacker recover
// the token; the argon2id hash is still the authenticator.
func tokenID(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// hashToken returns (hash, salt) for a bearer token. The raw token is never stored; subsequent
// verification calls hashToken with the stored salt and compares constant-time.
func hashToken(token string) (hash, salt []byte, err error) {
	salt = make([]byte, argonSaltLen)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generate salt: %w", err)
	}
	hash = argon2.IDKey([]byte(token), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return hash, salt, nil
}

// verifyToken returns true when `token` hashes to `wantHash` under `salt`. Uses subtle.ConstantTimeCompare
// to prevent the hash-compare step from leaking timing info.
func verifyToken(token string, wantHash, salt []byte) bool {
	if len(wantHash) == 0 || len(salt) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(token), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, wantHash) == 1
}

// ErrTokenMismatch is returned when a presented token does not match any enrolled host.
var ErrTokenMismatch = errors.New("enrollment: token mismatch")
