// Package keyring derives purpose-specific cryptographic keys from a single high-entropy server root secret using HKDF-SHA256.
//
// The pattern is key separation (RFC 5869): one provisioned root secret (EDR_SECRET_KEY) seeds an unbounded number of independent
// subkeys, each bound to a distinct, versioned domain-separation label. Because HKDF-Expand is a PRF, a derived key reveals nothing
// about the root or about any sibling key, so a feature that needs a server-side key calls Derive with a new label rather than asking
// an operator to provision another secret. This is the same model Rails (secret_key_base) and Django (SECRET_KEY) use.
//
// Use this only for long-lived server-side keys (HMAC peppers, cookie-signing keys). Per-record random values (nonces, one-time
// tokens, per-row salts) must be generated with crypto/rand, not derived here.
package keyring

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// MinRootKeyLen is the floor for the root secret. 32 bytes matches the HKDF-SHA256 output width: a shorter root would cap the
// entropy of every derived key regardless of how long the derived output is requested.
const MinRootKeyLen = 32

// Domain-separation labels for the long-lived keys derived from the deployment root secret. They live here, not in a single cmd, so
// every server binary derives from the identical label: a host token minted (or session cookie signed) by one binary must validate
// under another running the same root secret, which only holds if they pass the same Derive label. Each is versioned so a single
// purpose can be rotated by bumping its suffix without disturbing the root or any sibling key.
const (
	HostTokenSigningLabel  = "edr/host-token/sign/v1" //nolint:gosec // G101: HKDF domain-separation label, not a credential
	SessionSigningKeyLabel = "edr/session/signing/v1"
	// OIDCClientSecretLabel derives the AES-256-GCM key that seals the stored OIDC client secret at rest (issue #375). The secret is
	// persisted only in sealed form; rotating EDR_SECRET_KEY (or bumping this label's version) makes the stored ciphertext
	// undecryptable, after which an operator re-enters the client secret through the admin UI.
	OIDCClientSecretLabel = "edr/oidc/client-secret/v1" //nolint:gosec // G101: HKDF domain-separation label, not a credential
	// ServiceAccountTokenSigningLabel derives the HMAC-SHA256 key that signs service-account access tokens (issue #376, ADR-0013).
	// Distinct from the host-token label so the two self-validating token families are cryptographically separated even though both
	// are HMAC over the same root. The literal matches ADR-0013 and the openspec change artifacts.
	ServiceAccountTokenSigningLabel = "edr/service-account-token/sign/v1" //nolint:gosec // G101: HKDF domain-separation label, not a credential
	// WebhookSecretSealLabel derives the AES-256-GCM key that seals outbound-webhook per-destination signing secrets at rest (issue
	// #496). Distinct from the OIDC label so the two sealed-secret families are cryptographically separated; rotating EDR_SECRET_KEY
	// (or bumping this version) makes stored destination secrets undecryptable, after which an operator re-enters them.
	WebhookSecretSealLabel = "edr/webhook/secret-seal/v1" //nolint:gosec // G101: HKDF domain-separation label, not a credential
)

// derivedKeyLen is the byte length of every derived key. 32 bytes is a full HMAC-SHA256 key and an ample HMAC/AEAD key budget.
const derivedKeyLen = 32

// Keyring derives subkeys from a root secret. It holds a private copy of the root, so callers may reuse or zero their input buffer
// after construction.
type Keyring struct {
	root []byte
}

// New constructs a Keyring from the root secret. It returns an error when the root is shorter than MinRootKeyLen; callers that load
// the root from validated config (which already enforces the floor) can treat the error as a defensive invariant.
func New(root []byte) (*Keyring, error) {
	if len(root) < MinRootKeyLen {
		return nil, fmt.Errorf("keyring: root key must be at least %d bytes, got %d", MinRootKeyLen, len(root))
	}
	return &Keyring{root: bytes.Clone(root)}, nil
}

// Derive returns the 32-byte key bound to label. The label is the HKDF info string and is the sole domain separator: distinct labels
// yield independent keys, and a fixed label is stable across calls and process restarts, so a derived key can authenticate data it
// produced earlier. Labels SHOULD be namespaced and versioned (e.g. "edr/host-token/sign/v1") so a single purpose can be rotated by
// bumping its version without disturbing the root or sibling keys.
func (k *Keyring) Derive(label string) []byte {
	// HKDF-SHA256 Extract-then-Expand. The root is already high-entropy, so the Extract salt is nil per RFC 5869 guidance; the label
	// is the Expand info. hkdf.Key only errors when keyLength exceeds 255*HashLen, which derivedKeyLen never does, so a non-nil error
	// here is an unreachable programming error rather than a runtime condition.
	key, err := hkdf.Key(sha256.New, k.root, nil, label, derivedKeyLen)
	if err != nil {
		panic(fmt.Sprintf("keyring: derive %q: %v", label, err))
	}
	return key
}
