// Package ssoconfig owns the oidc_config table: the deployment's single, durable, runtime-editable OIDC provider configuration
// (issue #375). It persists issuer, client id, redirect URL, scopes, JIT toggle, default role, and the client secret sealed at rest,
// and is the runtime source of truth the OIDC login path resolves its provider from. Env vars (EDR_OIDC_*) only seed the row on first
// boot; the stored row governs thereafter.
package ssoconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Sealer encrypts and decrypts the OIDC client secret at rest with AES-256-GCM under a key derived from the deployment root secret
// (keyring label edr/oidc/client-secret/v1). The sealed form is nonce || ciphertext||tag; a fresh random 96-bit nonce per Seal keeps
// GCM safe across rotations. Plaintext secrets are never persisted and never returned over the API: only the sealed blob is stored.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte key (keyring.Derive output width). Returns an error if the key is not a valid AES key
// length, which for a keyring-derived key is a defensive invariant rather than a runtime condition.
func NewSealer(key []byte) (*Sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ssoconfig: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ssoconfig: new gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal returns nonce || GCM(plaintext). The nonce is prepended so Open can recover it; GCM's tag (appended by Seal) authenticates
// both the ciphertext and the nonce, so a tampered blob fails to open.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ssoconfig: nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to its first arg (the nonce), yielding nonce || ciphertext||tag in one allocation.
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal. It returns an error when the blob is shorter than a nonce or when authentication fails (wrong key, truncation,
// or tampering), so a stored secret that cannot be decrypted surfaces as an explicit error the login path maps to "re-enter the
// client secret" rather than a silent empty secret.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("ssoconfig: sealed value too short")
	}
	nonce, ciphertext := sealed[:ns], sealed[ns:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ssoconfig: open: %w", err)
	}
	return plaintext, nil
}
