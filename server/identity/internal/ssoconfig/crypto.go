// Package ssoconfig owns the oidc_config table: the deployment's single, durable, runtime-editable OIDC provider configuration
// (issue #375). It persists issuer, client id, scopes, JIT toggle, default role, and the client secret sealed at rest, and is the
// runtime source of truth the OIDC login path resolves its provider from. The redirect URI is NOT stored here: it is derived at read
// time from the deployment external URL (kept in the appconfig document) via RedirectURLFor. Env vars (EDR_OIDC_*) only seed the row on
// first boot; the stored row governs thereafter.
package ssoconfig

import "github.com/fleetdm/edr/internal/secretseal"

// Sealer and NewSealer re-export the shared AES-256-GCM sealer from internal/secretseal. The implementation was factored out of this
// package (issue #496) so the detection outbound-webhook config can seal its per-destination signing secrets with the same audited
// code rather than a clone. The OIDC client secret is sealed under the keyring label edr/oidc/client-secret/v1 (see identity bootstrap).
type Sealer = secretseal.Sealer

// NewSealer builds a Sealer from a 32-byte key (keyring.Derive output width). See secretseal.NewSealer.
var NewSealer = secretseal.NewSealer
