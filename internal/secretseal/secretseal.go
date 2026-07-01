// Package secretseal encrypts and decrypts small secrets at rest with AES-256-GCM under a caller-supplied 32-byte key (typically a
// keyring.Derive output). It is the shared sealer both the identity SSO config (the OIDC client secret) and the detection outbound
// webhook config (per-destination signing secrets) use, so the sealing implementation lives in one audited place rather than being
// cloned per bounded context. The sealer is key-agnostic: it never reaches into a keyring itself; callers derive and pass the key.
package secretseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// aes256KeyLen is the required key length for the AES-256-GCM sealer. aes.NewCipher also accepts 16- and 24-byte keys (AES-128/192);
// pinning 32 here keeps the implementation matching the documented AES-256 property instead of silently downgrading on a short key.
const aes256KeyLen = 32

// Sealer encrypts and decrypts a secret at rest with AES-256-GCM under a key derived from the deployment root secret. The sealed form
// is nonce || ciphertext||tag; a fresh random 96-bit nonce per Seal keeps GCM safe across rotations. Plaintext secrets are never
// persisted and never returned over the API: only the sealed blob is stored.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte key (keyring.Derive output width). It REQUIRES exactly 32 bytes so the cipher is always
// AES-256; a shorter key (which aes.NewCipher would otherwise accept as AES-128/192) is rejected as a defensive invariant.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != aes256KeyLen {
		return nil, fmt.Errorf("secretseal: sealer key must be %d bytes (AES-256), got %d", aes256KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretseal: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretseal: new gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal returns nonce || GCM(plaintext). The nonce is prepended so Open can recover it; GCM's tag (appended by Seal) authenticates
// both the ciphertext and the nonce, so a tampered blob fails to open.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secretseal: nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to its first arg (the nonce), yielding nonce || ciphertext||tag in one allocation.
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal. It returns an error when the blob is shorter than a nonce or when authentication fails (wrong key, truncation,
// or tampering), so a stored secret that cannot be decrypted surfaces as an explicit error the caller maps to "re-enter the secret"
// rather than a silent empty secret.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("secretseal: sealed value too short")
	}
	nonce, ciphertext := sealed[:ns], sealed[ns:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("secretseal: open: %w", err)
	}
	return plaintext, nil
}
